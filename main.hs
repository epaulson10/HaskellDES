import System.Environment
import System.IO
import System.Directory
import System.Exit
import DES
import Crypto.Hash.SHA256 ( hash )
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString as B

main :: IO ()
main = do
    args <- getArgs
    (command,infile,outfile, password) <- parseArgs args
    -- password <- getPassword
    fileContents <- B.readFile infile
    let key = BC.take 64 $ hash $ BC.pack password 
        process = if command == "encrypt" then encryptByteString else decryptByteString
        in  B.writeFile outfile $ process key fileContents
    return ()

encryptByteString :: B.ByteString -> B.ByteString -> B.ByteString
encryptByteString key contents =  (B.concat .  map (`encrypt` key) . pad . chunk) contents
decryptByteString :: B.ByteString -> B.ByteString -> B.ByteString
decryptByteString key contents = (B.concat . unpad . map (`decrypt` key) . chunk) contents

parseArgs :: [String] -> IO (String, String, String, String)
parseArgs [cmd, infile, outfile] = do
    inputExists <- doesFileExist infile
    if (cmd /= "encrypt" && cmd /= "decrypt") || not inputExists then
        usage >> exitFailure
    else do
        password <- getPassword
        return (cmd, infile, outfile, password)
parseArgs ["-p", password, cmd, infile, outfile] = do
    inputExists <- doesFileExist infile
    if (cmd /= "encrypt" && cmd /= "decrypt") || not inputExists then
        usage >> exitFailure
    else
        return (cmd, infile, outfile, password)

parseArgs _ = usage >> exitFailure

    

usage :: IO()
usage = do
    progName <- getProgName 
    putStrLn $ progName ++ " {-p password} [encrypt,decrypt] infile outfile"

getPassword :: IO String
getPassword = do
    putStr "Enter the password: "
    oldEchoVal <- hGetEcho stdin
    hSetEcho stdin False
    pass <- getLineSecret
    putChar '\n'
    putStr "Reenter the password: "
    pass2 <- getLineSecret
    putChar '\n'
    hSetEcho stdin oldEchoVal
    if pass /= pass2 then do
        putStrLn "*Passwords didn't match*"
        pass <- getPassword
        return pass
    else
        return pass

getLineSecret :: IO String
getLineSecret = do
    c <- getChar
    if c == '\n' then 
        return []
     else
         do cs <- getLineSecret
            return (c:cs)

chunk :: BC.ByteString -> [BC.ByteString]
chunk bytestring  = if BC.length bytestring == 0 then
                        []
                    else [BC.take 8 bytestring] ++ (chunk $ BC.drop 8 bytestring)

pad :: [BC.ByteString] -> [BC.ByteString]
pad xs =  
    if B.length finalBlock == 8 then
        let padArray = 1:(take 7 $ repeat 0)
        in  xs ++ [B.pack padArray]
    else
        let numZeroesNeeded = 7 - finalBlockLen
            padArray = 128:(take numZeroesNeeded $ repeat 0)
        in  (init xs) ++ [B.append finalBlock (B.pack padArray)]
    where finalBlock = last xs
          finalBlockLen = B.length finalBlock

unpad :: [BC.ByteString] -> [BC.ByteString]
unpad xs = 
   (init xs) ++ [origBytes] -- orig bytes could be empty in the case of a perfect block size
   where finalBlock = last xs
         origBytes = B.reverse $ B.drop 1 $ B.dropWhile (0 ==) $ B.reverse finalBlock
