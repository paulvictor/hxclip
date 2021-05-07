{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Main(main) where

import Data.Maybe (fromMaybe)
import System.Environment (lookupEnv)
import qualified Crypto.Gpgme as GPG
import qualified Data.ByteString.Char8 as BS
import qualified Graphics.X11.Xlib.Display as X
import qualified Graphics.X11.Xlib.Atom as X
import qualified Graphics.X11.Xlib.Window as X
import qualified Graphics.X11.Xlib.Extras as X
import qualified Graphics.X11.Xlib.Event as X
import qualified Graphics.X11.Types as X
import qualified Graphics.X11.Xlib.Types as X
import qualified Libnotify.C.Notify as LN
import qualified Libnotify.C.NotifyNotification as LN
import Data.IORef (IORef, newIORef, writeIORef, readIORef)
import Foreign.C.String (castCCharToChar, castCharToCChar)
import System.IO (hPutStr, stderr)
import System.IO.Unsafe (unsafePerformIO)
import Control.Monad (forever, when)
import Data.ByteString (ByteString)
import Data.Functor (void, (<&>))
import Options.Applicative

data ClipBoard
  = ClipBoard
  { contents :: ByteString
  , storedEncrypted :: Bool }

display :: X.Display
display = unsafePerformIO $
  lookupEnv "DISPLAY" >>= maybe (error "$DISPLAY is not set") X.openDisplay

clipboard :: X.Atom
clipboard = unsafePerformIO $ X.internAtom display "CLIPBOARD" False

passwordClipboard :: X.Atom
passwordClipboard = unsafePerformIO $ X.internAtom display "SECONDARY" False

incr :: X.Atom
incr = unsafePerformIO $ X.internAtom display "INCR" False

passwordString :: X.Atom
passwordString = unsafePerformIO $ X.internAtom display "UTF8_STRING" False

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

shouldUseLibNotificationRef :: IORef Bool
shouldUseLibNotificationRef = unsafePerformIO $ newIORef True

main :: IO ()
main = do
  pubKey <-
     getPubKeyFromCLIArgs <&>
       fromMaybe (error "Unable to initialize key with specified fingerprint")
  rootWindow <-
    X.rootWindow display (X.defaultScreen display)
  window <-
    X.createSimpleWindow display rootWindow (-10) (-10) 1 1 0 0 0
  -- clipBoardContents :: IORef (Maybe ClipBoard)
  clipBoardRef <- newIORef Nothing
  LN.notify_init "hxclip" >>= writeIORef shouldUseLibNotificationRef
  -- This can be lossy initially since we maintain both in a single buffer.
  -- We give preference to the password clipboard
  grabClipBoard window pubKey clipboard clipBoardRef
  grabClipBoard window pubKey passwordClipboard clipBoardRef
  forever $
    manageClipBoard window pubKey clipBoardRef
  where
  getPubKeyFromCLIArgs = do
    fingerprint <-
      execParser $ info optionsParser fullDesc
    runInDefaultCtx $ \ctx -> GPG.getKey ctx fingerprint GPG.NoSecret
  optionsParser :: Parser ByteString
  optionsParser =
    BS.pack <$> (strOption $ long "gpg-fingerprint")

manageClipBoard :: X.Window -> GPG.Key -> IORef (Maybe ClipBoard) -> IO ()
manageClipBoard window gPGKey clipBoardRef = do
  (eventType, event) <-
    X.allocaXEvent (\xevPtr -> do
      X.nextEvent display xevPtr
      (,) <$> X.get_EventType xevPtr <*> X.getEvent xevPtr)
  if
    | eventType == X.selectionClear ->
      -- Some other application copied data into the selection. Take over!!
      case event of
        (X.SelectionClear _ _ _ _ evWindow evSelection _) -> do
          windowName <-
            maybe "" ("from " <>) <$> X.fetchName display evWindow
          (X.getAtomName display evSelection) >>= maybe
            (output $ "Unable to get clipboard name")
            (\name -> output $ "Lost control of " <> name <> windowName <> ". Regaining now..")
          grabClipBoard window gPGKey evSelection clipBoardRef
        _ -> output $ "Unexpected event : " <> show event
    | eventType == X.selectionRequest ->
       case event of
         (X.SelectionRequest _ _ _ _ _ evRequestor evSelection evTarget evProp _) ->
           if evSelection == passwordClipboard
           then do
             output $ "Not serving the password clipboard directly. Use the clipboard"
             deny evRequestor evSelection evTarget
           else
             -- Else doesn't work if managing more than one 2 clipboards
             readIORef clipBoardRef >>= maybe
               (deny evRequestor evSelection evTarget)
               (\cboard ->
                 if evTarget == utf8String && evProp /= X.none
                 then
                   if storedEncrypted cboard
                   then runInDefaultCtx $ \ctx ->
                     GPG.decrypt ctx (contents cboard) >>=
                       either
                       (\err -> output $ "Decryption failed : " <> show err)
                       (fulfill evRequestor evSelection evTarget evProp)
                   else fulfill evRequestor evSelection evTarget evProp (contents cboard)
                 else (deny evRequestor evSelection evTarget))
         _ -> output $ "Unexpected event : " <> show event
    | otherwise -> manageClipBoard window gPGKey clipBoardRef

grabClipBoard :: X.Window -> GPG.Key -> X.Atom -> IORef (Maybe ClipBoard) -> IO ()
grabClipBoard window gPGKey selAtom clipboardRef = do
  owner <- X.xGetSelectionOwner display selAtom
  if owner == X.none
  then do
    (X.getAtomName display selAtom) >>= maybe
      (output $ "Unable to get clipboard name, still getting hold")
      (\name -> output $ "Getting hold of " <> name <> " from no previous owner")
    X.xSetSelectionOwner display selAtom window X.currentTime
  else do
    X.xConvertSelection display selAtom utf8String hxclip window X.currentTime
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
            when (not $ BS.null bs) $ -- This check is needed because password managers clear passwords
              if selAtom == passwordClipboard
              then runInDefaultCtx $
                \ctx ->
                  GPG.encrypt ctx [gPGKey] GPG.NoFlag bs >>=
                    either
                      (\err -> output $ "Encryption failed " <> show err)
                      (\encrypted -> writeIORef clipboardRef $ Just $ ClipBoard encrypted True)
              else writeIORef clipboardRef $ Just $ ClipBoard bs False
            X.deleteProperty display window selAtom
            X.xSetSelectionOwner display selAtom window X.currentTime)
    else serveSelectionNotify

deny :: X.Window -> X.Atom -> X.Atom -> IO ()
deny requestor selection target =
  X.allocaXEvent (\xEvPtr -> do
    X.setSelectionNotify xEvPtr requestor selection target X.none X.currentTime
    X.sendEvent display requestor True X.noEventMask xEvPtr)

fulfill :: X.Window -> X.Atom -> X.Atom -> X.Atom -> ByteString -> IO ()
fulfill requestor selection target prop bs =
  X.allocaXEvent (\xEvPtr -> do
    X.changeProperty8 display requestor prop utf8String X.propModeReplace $
      castCharToCChar <$> BS.unpack bs
    X.setSelectionNotify xEvPtr requestor selection target prop X.currentTime
    X.sendEvent display requestor True X.noEventMask xEvPtr)

--TODO : Send a desktop notification
output :: String -> IO ()
output message = do
  hPutStr stderr message
  readIORef shouldUseLibNotificationRef >>= \b ->
    when b $
      LN.notify_notification_new "" message "" >>= void . LN.notify_notification_show
