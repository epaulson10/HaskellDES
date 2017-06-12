module TestingDes ( hexToByteString ) where
import DES
import Data.List.Split -- splitOn
import Data.Char -- digitToInt
import Data.Word
import Control.Monad
import qualified Data.ByteString as B


main = do
    fileContents <- readFile "testvectors.txt"
    -- Remove any comments from the file
    lines <- return $ filter (\x -> head x /= '#') (lines fileContents)
    results <- return $ map processTestCase lines
    findFails results lines
    return ()

findFails :: [Bool] -> [String] -> IO ()
findFails [] [] = return ()
findFails (x:xs) (y:ys) = do
    when (x == False) (putStrLn ("Failed on testcase " ++ y))
    findFails xs ys

    

processTestCase :: String -> Bool
processTestCase str = 
    if encrypt pt key == ct then True else False
    where values = splitOn " " str
          key = hexToByteString $ values !! 0
          pt  = hexToByteString $ values !! 1
          ct  = hexToByteString $ values !! 2

hexToDigitString :: String -> [Word8]
hexToDigitString [] = []
hexToDigitString str = 
    (fromIntegral $ sixteenTerm * 16 + oneTerm): hexToDigitString (drop 2 str)
    where [first,second] = take 2 str 
          sixteenTerm = digitToInt first
          oneTerm     = digitToInt second

hexToByteString = (B.pack . hexToDigitString)
