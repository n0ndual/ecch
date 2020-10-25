package chameleon

import(
        "fmt"
        "crypto/elliptic"
        "crypto/rand"
        "crypto/sha256"
        "math/big"
        "io"
)

var curve = elliptic.P256()
var one = new(big.Int).SetInt64(1)

func neg(y *big.Int) (modNegY *big.Int){
     y.Neg(y)
     modNegY = y.Mod(y, curve.Params().P)
     return modNegY
}

func scalarRand() (x *big.Int, err error){
     params := curve.Params()
     b := make([]byte, params.BitSize/8+8)
     _, err = io.ReadFull(rand.Reader, b)
     if err != nil {
                return
     }
     x = new(big.Int).SetBytes(b)
     n := new(big.Int).Sub(params.N, one)
     x.Mod(x, n)
     x.Add(x, one)
     return
}

func pointRand() (x *big.Int, y *big.Int, err error){
     s, err := scalarRand()
     x, y = curve.ScalarBaseMult(s.Bytes())
     return
}

func computeHash(message string, rX *big.Int, rY *big.Int, s *big.Int, pubX *big.Int, pubY *big.Int) (hX, hY *big.Int){
     sha256Hash := sha256.New()
     sha256Hash.Write([]byte(message))
     sha256Hash.Write(rX.Bytes())
     sha256Hash.Write(rY.Bytes())
     sha256HashBytes:= sha256Hash.Sum(nil);

     t1X, t1Y := curve.ScalarMult(pubX, pubY, sha256HashBytes)
     negT1X, negT1Y := t1X, neg(t1Y)

     // r2 = s * basepoint
     t2X, t2Y := curve.ScalarBaseMult(s.Bytes())
     negT2X, negT2Y := t2X, neg(t2Y)

     // h = r + r1 + r2
     t3X, t3Y := curve.Add(rX, rY, negT1X, negT1Y)
     hX, hY = curve.Add(t3X, t3Y, negT2X, negT2Y)

     return
}

func ComputeHash(message string, pubX *big.Int, pubY *big.Int) (rX, rY, s, hashX *big.Int){
     rX, rY, _ = pointRand()
     s, _ = scalarRand()
     hashX, _ = computeHash(message, rX, rY, s, pubX, pubY)
     return
}

func VerifyHash(message string, rX *big.Int, rY *big.Int, s *big.Int, pubX *big.Int, pubY *big.Int, hashX *big.Int) (toBe bool){
     hX, _ := computeHash(message, rX, rY, s, pubX, pubY)
     toBe = hX.Cmp(hashX) == 0
     return
}

func FindCollision(message string, rX *big.Int, rY *big.Int, s *big.Int, hashX *big.Int, newMessage string, priv []byte) (newRX, newRY, newS *big.Int){
     params := curve.Params()
     pubX, pubY := curve.ScalarBaseMult(priv)
     hX, hY := computeHash(message, rX, rY, s, pubX, pubY)
     if(hashX.Cmp(hX) !=0){
         fmt.Println("check hash of orginal message failed, exit")
     }

     // new random K
     k,_ := scalarRand()
     //t1 = k * basepoint
     t1X, t1Y := curve.ScalarBaseMult(k.Bytes())
     // new_r = h + t1
     newRX, newRY = curve.Add(hX, hY, t1X, t1Y)
     // s' = k - H'*priv
     sha256Hash := sha256.New()
     sha256Hash.Write([]byte(newMessage))
     sha256Hash.Write(newRX.Bytes())
     sha256Hash.Write(newRY.Bytes())
     sha256HashBytes:= sha256Hash.Sum(nil);
     sha256HashInt := new(big.Int).SetBytes(sha256HashBytes)

     // t2 = H' * priv % N
     // new_s = k - t2 % N
     t2 := new(big.Int).Mod(new(big.Int).Mul(sha256HashInt, new(big.Int).SetBytes(priv)), params.N)
     newS = new(big.Int).Mod(new(big.Int).Sub(k, t2), params.N)
     return
}