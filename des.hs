import qualified Data.ByteString.Char8 as BC
import Data.Bits
import Data.Word
import Test.HUnit

{- These tables here were copy-pasted from this lovely
 - Wikipedia page: https://en.wikipedia.org/wiki/DES_supplementary_material
 - TODO: Wikipedia says that bit number 1 is the most significant bit. I may be mistaking 
 - this here.
 -}
initialPermutation = map (\x -> x-1) [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9 , 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7]

finalPermutation = map (\x -> x-1) [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9 , 49, 17, 57, 25]

expansionTable = map (\x -> x-1)[
    32, 1 , 2 , 3 , 4 , 5,
    4 , 5 , 6 , 7 , 8 , 9,
    8 , 9 , 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1]

permutationTable = map (\x -> x-1)[
    16, 7 , 20, 21, 29, 12, 28, 17,
    1 , 15, 23, 26, 5 , 18, 31, 10,
    2 , 8 , 24, 14, 32, 27, 3 , 9,
    19, 13, 30, 6 , 22, 11, 4 , 25]

permutedChoiceOneL = map (\x -> x-1)[
    7 , 49, 41, 33, 25, 17, 9,
    1 , 58, 50, 42, 34, 26, 18,
    10, 2 , 59, 51, 43, 35, 27,
    19, 11, 3 , 60, 52, 44, 36]

permutedChoiceOneR = map (\x -> x-1)[
    63, 55, 47, 39, 31, 23, 15,
    7 , 62, 54, 46, 38, 30, 22,
    14, 6 , 61, 53, 45, 37, 29,
    21, 13, 5 , 28, 20, 12, 4]

permutedChoiceTwo = map (\x -> x-1)[
    14, 17, 11, 24, 1 , 5,
    3 , 28, 15, 6 , 21, 10,
    23, 19, 12, 4 , 26, 8,
    16, 7 , 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32]

-- Substitution Boxes
s1 =
    [14, 4 , 13, 1 , 2 , 15, 11, 8 , 3 , 10, 6 , 12, 5 , 9 , 0 , 7,
    0 , 15, 7 , 4 , 14, 2 , 13, 1 , 10, 6 , 12, 11, 9 , 5 , 3 , 8,
    4 , 1 , 14, 8 , 13, 6 , 2 , 11, 15, 12, 9 , 7 , 3 , 10, 5 , 0,
    15, 12, 8 , 2 , 4 , 9 , 1 , 7 , 5 , 11, 3 , 14, 10, 0 , 6 , 13]
s2 =
    [15, 1 , 8 , 14, 6 , 11, 3 , 4 , 9 , 7 , 2 , 13, 12, 0 , 5 , 10,
    3 , 13, 4 , 7 , 15, 2 , 8 , 14, 12, 0 , 1 , 10, 6 , 9 , 11, 5,
    0 , 14, 7 , 11, 10, 4 , 13, 1 , 5 , 8 , 12, 6 , 9 , 3 , 2 , 15,
    13, 8 , 10, 1 , 3 , 15, 4 , 2 , 11, 6 , 7 , 12, 0 , 5 , 14, 9]
s3 =
    [10, 0 , 9 , 14, 6 , 3 , 15, 5 , 1 , 13, 12, 7 , 11, 4 , 2 , 8,
    13, 7 , 0 , 9 , 3 , 4 , 6 , 10, 2 , 8 , 5 , 14, 12, 11, 15, 1,
    13, 6 , 4 , 9 , 8 , 15, 3 , 0 , 11, 1 , 2 , 12, 5 , 10, 14, 7,
    1 , 10, 13, 0 , 6 , 9 , 8 , 7 , 4 , 15, 14, 3 , 11, 5 , 2 , 12]
s4 =
    [7 , 13, 14, 3 , 0 , 6 , 9 , 10, 1 , 2 , 8 , 5 , 11, 12, 4 , 15,
    13, 8 , 11, 5 , 6 , 15, 0 , 3 , 4 , 7 , 2 , 12, 1 , 10, 14, 9,
    10, 6 , 9 , 0 , 12, 11, 7 , 13, 15, 1 , 3 , 14, 5 , 2 , 8 , 4,
    3 , 15, 0 , 6 , 10, 1 , 13, 8 , 9 , 4 , 5 , 11, 12, 7 , 2 , 14]
s5 =
    [2 , 12, 4 , 1 , 7 , 10, 11, 6 , 8 , 5 , 3 , 15, 13, 0 , 14, 9,
    14, 11, 2 , 12, 4 , 7 , 13, 1 , 5 , 0 , 15, 10, 3 , 9 , 8 , 6,
    4 , 2 , 1 , 11, 10, 13, 7 , 8 , 15, 9 , 12, 5 , 6 , 3 , 0 , 14,
    11, 8 , 12, 7 , 1 , 14, 2 , 13, 6 , 15, 0 , 9 , 10, 4 , 5 , 3]
s6 =
    [12, 1 , 10, 15, 9 , 2 , 6 , 8 , 0 , 13, 3 , 4 , 14, 7 , 5 , 11,
    10, 15, 4 , 2 , 7 , 12, 9 , 5 , 6 , 1 , 13, 14, 0 , 11, 3 , 8,
    9 , 14, 15, 5 , 2 , 8 , 12, 3 , 7 , 0 , 4 , 10, 1 , 13, 11, 6,
    4 , 3 , 2 , 12, 9 , 5 , 15, 10, 11, 14, 1 , 7 , 6 , 0 , 8 , 13]
s7 = 
    [4 , 11, 2 , 14, 15, 0 , 8 , 13, 3 , 12, 9 , 7 , 5 , 10, 6 , 1,
    13, 0 , 11, 7 , 4 , 9 , 1 , 10, 14, 3 , 5 , 12, 2 , 15, 8 , 6,
    1 , 4 , 11, 13, 12, 3 , 7 , 14, 10, 15, 6 , 8 , 0 , 5 , 9 , 2,
    6 , 11, 13, 8 , 1 , 4 , 10, 7 , 9 , 5 , 0 , 15, 14, 2 , 3 , 12]
s8 = 
    [13, 2 , 8 , 4 , 6 , 15, 11, 1 , 10, 9 , 3 , 14, 5 , 0 , 12, 7,
    1 , 15, 13, 8 , 10, 3 , 7 , 4 , 12, 5 , 6 , 11, 0 , 14, 9 , 2,
    7 , 11, 4 , 1 , 9 , 12, 14, 2 , 0 , 6 , 10, 13, 15, 3 , 5 , 8,
    2 , 1 , 14, 7 , 4 , 10, 8 , 13, 15, 12, 9 , 0 , 3 , 5 , 6 , 11]

byteToBitVector :: Word8 -> BitVector
byteToBitVector byte = BitVector  [ testBit byte n | n <- [0..3]]

bitVectorToInt :: BitVector -> Int
bitVectorToInt (BitVector bits) = foldl (.|.) 0 [ if bit then num else 0 | (bit, num) <- zip bits powersOfTwo]
    where powersOfTwo = [ 2^n | n <- [0..]]

sboxes :: [[Word8]]
sboxes = [s1,s2,s3,s4,s5,s6,s7,s8]

sboxLookup :: BitVector -> [Word8] -> BitVector
sboxLookup (BitVector bits) sbox = byteToBitVector $ sbox !! (row*16 + col)
    where row = bitVectorToInt $ BitVector ((last bits):(head bits):[])
          col = bitVectorToInt $ BitVector (init . tail $ bits)

numRotations :: Int -> Int
numRotations round =
    if elem round oneRotationRounds
        then 1
        else 2
    where oneRotationRounds = [1,2,9,16]

newtype BitVector = BitVector [Bool] deriving Show  

class Vector a where
    concatVec :: a -> a -> a

instance Vector BitVector where 
    concatVec (BitVector xs) (BitVector ys) = BitVector (xs++ys)

data ByteArray = ByteArray [Word8] deriving Show

instance Eq ByteArray where
    ByteArray xs == ByteArray ys = and $ map (0 ==) [ xor x  y | (x,y) <- zip xs ys] 

xorBool :: Bool -> Bool -> Bool
xorBool True False = True 
xorBool False True = True 
xorBool _ _ = False

instance Eq BitVector where
    BitVector xs == BitVector ys = (not . or) [ xorBool x y | (x,y) <- zip xs ys ]

instance Bits BitVector where
    BitVector xs .&. BitVector ys = BitVector [ x && y | (x,y) <- zip xs ys]
    BitVector xs .|. BitVector ys = BitVector [ x || y | (x,y) <- zip xs ys]
    BitVector xs `xor` BitVector ys = BitVector [ xor x y | (x,y) <- zip xs ys]
    complement (BitVector xs) = BitVector [ not x | x <- xs ]
    isSigned (BitVector x) = False -- We don't care about the sign of this datatype
    bit n = BitVector (listConstructor n)
         where listConstructor 0 = True:(repeat False)
               listConstructor x = False:(listConstructor (x-1))
    {- The shift functions are confusing because the least significant bits are
     - placed at the front of the list, so shiftL actually shifts the underlying
     - list right, and vice versa -}
    shiftL (BitVector xs) 0 = BitVector xs
    shiftL (BitVector xs) n = shiftL (BitVector (shiftOneL xs)) (n-1)
        where shiftOneL ys = False:(init ys)
    shiftR (BitVector xs) 0 = BitVector xs
    shiftR (BitVector xs) n = shiftR (BitVector (shiftOneR xs)) (n-1)
        where shiftOneR ys = (tail ys)++[False]
    rotateL (BitVector xs) 0 = BitVector xs
    rotateL (BitVector xs) n = rotateL (BitVector (rotateOneL xs)) (n-1) 
        where rotateOneL ys = (last ys):(init ys)
    rotateR (BitVector xs) 0 = BitVector xs
    rotateR (BitVector xs) n = rotateR (BitVector (rotateOneR xs)) (n-1) 
        where rotateOneR ys = (tail ys) ++ [head ys]
    bitSizeMaybe (BitVector xs) = Nothing
    bitSize (BitVector xs) = undefined
    popCount (BitVector xs) = foldl (+) 0 [ if x == True then 1 else 0 | x <- xs]
    testBit (BitVector xs) n = xs !! n
    -- By making bit n return an infinite list, the below two are no longer necessary
    --setBit (BitVector xs) n = BitVector [ if i == n then True else x | (x,i) <- zip xs [0..]]
    --clearBit (BitVector xs) n = BitVector [ if i == n then False else x | (x,i) <- zip xs [0..]]

testkey = BitVector ((take 32 $ repeat True) ++ (take 32 $ repeat False))

bitVecLen (BitVector xs) = length xs
combine :: BitVector -> BitVector -> BitVector
combine (BitVector xs) (BitVector ys) = BitVector (xs ++ ys)
split :: BitVector -> (BitVector, BitVector)
split (BitVector xs) = (BitVector left, BitVector right)
    where (left, right) = splitAt (length xs `div` 2) xs
chunk :: Int -> BitVector -> [BitVector]
chunk n (BitVector xs) = map BitVector (go xs) 
    where
        go [] = []
        go ys = take n ys : go (drop n ys)

pc1 :: BitVector -> (BitVector, BitVector)
pc1 (BitVector bits64) = (BitVector leftPermuted, BitVector rightPermuted)
    where leftPermuted = [ bits64 !! n | n <- permutedChoiceOneL]
          rightPermuted = [ bits64 !!  n | n <- permutedChoiceOneR]

splitAndShift :: BitVector -> Int -> BitVector
splitAndShift vec round = combine (shiftL left n) (shiftL right n)
    where (left, right) = split vec
          n = numRotations round

pc2 :: BitVector -> BitVector
pc2 (BitVector bits56) = BitVector [ bits56 !! n | n <- permutedChoiceTwo]

permutation :: BitVector -> BitVector
permutation (BitVector bits32) = BitVector [ bits32 !! n | n <- permutationTable]

expansion :: BitVector -> BitVector
expansion (BitVector bits32) = BitVector [ bits32 !! n | n <- expansionTable]

genKeys :: BitVector -> [BitVector]
genKeys key = keyGenRound 16 (split key)

keyGenRound :: Int -> (BitVector,BitVector) -> [BitVector]
keyGenRound 0 _ = []
keyGenRound n (left,right) = (pc2 (combine rotatedL rotatedR)) : keyGenRound (n-1) (rotatedL, rotatedR)
    where rotatedL = rotateL left (numRotations n)
          rotatedR = rotateL right (numRotations n)

feistel :: BitVector -> BitVector -> BitVector
feistel halfBlock subkey = 
     permutation
     $ doSBoxes
     $ ((expansion halfBlock) `xor` subkey)
            where 
                doSBoxes :: BitVector -> BitVector
                doSBoxes bits = foldl concatVec (BitVector []) [ sboxLookup bv sbox  | (bv,sbox) <- zip (chunk 6 bits) sboxes]

encryptBlock :: BitVector -> BitVector ->  BitVector
encryptBlock (BitVector bits) key =  fp
    where 
          roundKeys = genKeys key
          ip = BitVector [ bits !! n | n <- initialPermutation ]
          (left,right) =  doRounds 0 roundKeys (split ip)
          (BitVector endBits) = concatVec left right
          fp = BitVector [ endBits !! n | n <- finalPermutation ] 

doRounds :: Int -> [BitVector] -> (BitVector,BitVector) -> (BitVector,BitVector)
doRounds 15 keys (left,right) = (newLeft, right)
    where newLeft = xor (feistel right (keys !! 15)) left

doRounds round keys (left, right) = doRounds (round + 1) keys (right, nextRight)
    where nextRight = xor (feistel right (keys !! round)) left


test1 = TestCase (
            assertEqual
            "keygen sizes"
            (length $ genKeys testkey)
            16)
test2 = TestCase (
            assertEqual
            "subkey size is 48 bits"
            ( bitVecLen $ head $ genKeys testkey)
            48)

tests = TestList [test1, test2]