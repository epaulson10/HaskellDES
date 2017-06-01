import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Bits
import System.Environment

oneTimePadEncrypt :: B.ByteString -> B.ByteString -> B.ByteString
oneTimePadEncrypt plaintext key = B.pack $ B.zipWith xor plaintext key

oneTimePadDecrypt = oneTimePadEncrypt

main :: IO ()
main = do 
    (ptfile:keyfile:outfile:_) <- getArgs
    text <- B.readFile ptfile
    key  <- B.readFile keyfile
    if B.length text /= B.length key then
        putStrLn "The input and key must be the same length"
    else
        B.writeFile outfile (oneTimePadEncrypt text key)
