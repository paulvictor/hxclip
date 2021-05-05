{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main(main) where

import Data.Maybe (fromMaybe)
import System.Environment (lookupEnv)
import qualified Graphics.X11.Xlib.Display as X
import qualified Graphics.X11.Xlib.Atom as X
import qualified Graphics.X11.Xlib.Window as X
import qualified Graphics.X11.Xlib.Extras as X
import qualified Graphics.X11.Xlib.Event as X
import qualified Graphics.X11.Types as X
import qualified Graphics.X11.Xlib.Types as X
import qualified Data.ByteString.Char8 as BS
import qualified Crypto.Gpgme as GPG
import Data.IORef (IORef, newIORef, writeIORef, readIORef)
import Foreign.C.String (castCCharToChar, castCharToCChar)
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad (forever)
import Data.ByteString (ByteString)
import System.Posix.Signals (installHandler, sigTERM, sigINT, Handler(CatchOnce))
import System.Exit (exitSuccess)
import Data.Functor (void, (<&>))
import Options.Applicative

display :: X.Display
display = unsafePerformIO $
  lookupEnv "DISPLAY" >>= maybe (error "$DISPLAY is not set") X.openDisplay
clipboard :: X.Atom
clipboard = unsafePerformIO $ X.internAtom display "CLIPBOARD" False
incr :: X.Atom
incr = unsafePerformIO $ X.internAtom display "INCR" False
utf8String :: X.Atom
utf8String = unsafePerformIO $ X.internAtom display "UTF8_STRING" False
hxclip :: X.Atom
hxclip = unsafePerformIO $ X.internAtom display "HXCLIP" False

runInDefaultCtx :: (GPG.Ctx -> IO a) -> IO a
runInDefaultCtx f = do
  gpghomedir <-
     lookupEnv "GNUPGHOME" <&>
       fromMaybe (error "GNUPGHOME not set")
  GPG.withCtx gpghomedir "C" GPG.OpenPGP f

main :: IO ()
main = do
  installSignalHandlers
  pubKey <-
     getPubKeyFromCLIArgs <&>
       fromMaybe (error "Unable to initialize key with specified fingerprint")
  rootWindow <-
    X.rootWindow display (X.defaultScreen display)
  window <-
    X.createSimpleWindow display rootWindow (-10) (-10) 1 1 0 0 0
  -- clipBoardContents :: IORef (Maybe ByteString)
  clipBoardRef <- newIORef Nothing
  grabClipBoard window pubKey clipBoardRef
  forever $
    serveClipBoard window pubKey clipBoardRef
  where
  installSignalHandlers = do
    void $ installHandler sigINT (CatchOnce exitSuccess) Nothing
    void $ installHandler sigTERM (CatchOnce exitSuccess) Nothing
  getPubKeyFromCLIArgs = do
    fingerprint <-
      execParser $ info optionsParser fullDesc
    runInDefaultCtx $ \ctx -> GPG.getKey ctx fingerprint GPG.NoSecret
  optionsParser :: Parser ByteString
  optionsParser =
    BS.pack <$> (strOption $ long "gpg-fingerprint")

serveClipBoard :: X.Window -> GPG.Key -> IORef (Maybe ByteString) -> IO ()
serveClipBoard window gPGKey clipBoardRef = do
  (eventType, event) <-
    X.allocaXEvent (\xevPtr -> do
      X.nextEvent display xevPtr
      (,) <$> X.get_EventType xevPtr <*> X.getEvent xevPtr)
  if
    | eventType == X.selectionClear -> do
     output $ "Lost control of clipboard. Regaining now"
     grabClipBoard window gPGKey clipBoardRef
    | eventType == X.selectionRequest ->
       case event of
         (X.SelectionRequest _ _ _ _ _ evRequestor evSelection evTarget evProp _) ->
           readIORef clipBoardRef >>=
             maybe
               (deny evRequestor evSelection evTarget)
               (\bs ->
                 if evTarget == utf8String && evProp /= X.none
                 then do
                   runInDefaultCtx $ \ctx ->
                     GPG.decrypt ctx bs >>=
                       either
                       (\err -> output $ "Decryption failed : " <> show err)
                       (fulfill evRequestor evSelection evTarget evProp)
                 else (deny evRequestor evSelection evTarget))
         _ -> output $ "Unexpected event : " <> show event
    | otherwise -> serveClipBoard window gPGKey clipBoardRef

deny :: X.Window -> X.Atom -> X.Atom -> IO ()
deny requestor selection target =
  X.allocaXEvent (\xEvPtr -> do
    X.setSelectionNotify xEvPtr requestor selection target X.none X.currentTime
    X.sendEvent display requestor True X.noEventMask xEvPtr)

fulfill :: X.Window -> X.Atom -> X.Atom -> X.Atom -> ByteString -> IO ()
fulfill requestor selection target prop contents =
  X.allocaXEvent (\xEvPtr -> do
    X.changeProperty8 display requestor prop utf8String X.propModeReplace $
      castCharToCChar <$> BS.unpack contents
    X.setSelectionNotify xEvPtr requestor selection target prop X.currentTime
    X.sendEvent display requestor True X.noEventMask xEvPtr)

grabClipBoard :: X.Window -> GPG.Key -> IORef (Maybe ByteString) -> IO ()
grabClipBoard window gPGKey clipboardRef = do
  owner <- X.xGetSelectionOwner display clipboard
  if owner == X.none
  then do
    output "Getting hold of clipboard from no previous owner"
    X.xSetSelectionOwner display clipboard window X.currentTime
  else do
    X.xConvertSelection display clipboard utf8String hxclip window X.currentTime
    serveSelectionNotify
  where
  serveSelectionNotify = do
    isSelectionNotify <-
      X.allocaXEvent (\xevPtr -> do
        X.nextEvent display xevPtr
        (X.get_EventType xevPtr <&> (== X.selectionNotify)))
    if isSelectionNotify
    then
      -- TODO : Handle INCR type
      X.getWindowProperty8 display hxclip window >>=
        maybe
          (output "getWindowProperty8 returned Nothing")
          (\cChars -> do
            output $
              "Getting ownership of " <> show (length cChars) <> " bytes of data"
            let
              bs = BS.copy $ BS.pack (castCCharToChar <$> cChars)
            runInDefaultCtx $
              \ctx ->
                GPG.encrypt ctx [gPGKey] GPG.NoFlag bs >>=
                  either
                    (\err -> output $ "Encryption failed " <> show err)
                    (\encrypted -> writeIORef clipboardRef $ Just encrypted)
            X.xSetSelectionOwner display clipboard window X.currentTime)
    else serveSelectionNotify

--TODO : Send a desktop notification
output :: String -> IO ()
output = putStrLn
