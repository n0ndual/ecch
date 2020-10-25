package chameleon

import(
    "testing"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/sha256"
    "crypto/ecdsa"
)

func TestComputeAndVerify(t *testing.T){
    _, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    rX, rY, s, hX := ComputeHash(message, pubX, pubY)
    toBe := VerifyHash(message, rX, rY, s, pubX, pubY, hX)
    if toBe != true {
        t.Errorf("verify hash failed")
    }
}

func TestFindCollision(t *testing.T){
    priv, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    rX, rY, s, hX := ComputeHash(message, pubX, pubY)
    newMessage := "hello shadowlands!"
    newRX, newRY, newS := FindCollision(message, rX, rY, s, hX, newMessage, priv)
    newHX,_ := computeHash(newMessage, newRX, newRY, newS, pubX, pubY)

    if(hX.Cmp(newHX) != 0){
        t.Errorf("verify hash failed")
    }
}

func BenchmarkComputeHash(b *testing.B) {
    _, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        ComputeHash(message, pubX, pubY)
    }
}

func BenchmarkFindCollision(b *testing.B) {
    priv, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    rX, rY, s, hX := ComputeHash(message, pubX, pubY)
    newMessage := "hello shadowlands!"
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        FindCollision(message, rX, rY, s, hX, newMessage, priv)
    }
}

func BenchmarkComputeChameleonHashWithoutRandom(b *testing.B){
    _, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    rX, rY, _ := pointRand()
    s, _ := scalarRand()
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        computeHash(message, rX, rY, s, pubX, pubY)
    }
}

func BenchmarkComputeChameleonHashWithoutScalarMult(b *testing.B){
    _, pubX, pubY, _ := elliptic.GenerateKey(curve, rand.Reader)
    message := "hello world!"
    rX, rY, _ := pointRand()
    s, _ := scalarRand()
    sha256Hash := sha256.New()
    sha256Hash.Write([]byte(message))
    sha256Hash.Write(rX.Bytes())
    sha256Hash.Write(rY.Bytes())
    sha256HashBytes:= sha256Hash.Sum(nil);
    t1X, t1Y := curve.ScalarMult(pubX, pubY, sha256HashBytes)
    negT1X, negT1Y := t1X, neg(t1Y)
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
         // r2 = s * basepoint
         t2X, t2Y := curve.ScalarBaseMult(s.Bytes())
         negT2X, negT2Y := t2X, neg(t2Y)
         t3X, t3Y := curve.Add(rX, rY, negT1X, negT1Y)
         curve.Add(t3X, t3Y, negT2X, negT2Y)
    }
}


func BenchmarkComputeSha256Hash(b *testing.B) {
    message := "hello world!"
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        sha256Hash := sha256.New()
        sha256Hash.Write([]byte(message))
        sha256Hash.Sum(nil);
    }
}

func BenchmarkEcdsaGenerate(b *testing.B) {
    pubkeyCurve := elliptic.P256()
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
    }
}


func BenchmarkEcdsaSign(b *testing.B) {
    message := "hello world!"
    pubkeyCurve := elliptic.P256()
    priv, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        sha256Hash := sha256.New()
        sha256Hash.Write([]byte(message))
        sha256HashBytes := sha256Hash.Sum(nil);
        ecdsa.Sign(rand.Reader, priv, sha256HashBytes)
    }
}

func BenchmarkEcdsaVerify(b *testing.B) {
    message := "hello world!"
    sha256Hash := sha256.New()
    sha256Hash.Write([]byte(message))
    sha256HashBytes := sha256Hash.Sum(nil)

    pubkeyCurve := elliptic.P256()
    priv, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
    pub := priv.PublicKey
    r, s, _ :=ecdsa.Sign(rand.Reader, priv, sha256HashBytes)
    signature := r.Bytes()
    signature = append(signature, s.Bytes()...)
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        ecdsa.Verify(&pub, sha256HashBytes, r, s)
    }
}

func BenchmarkEcdsaGenerateSignVerify(b *testing.B) {
    message := "hello world!"
    pubkeyCurve := elliptic.P256()
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        sha256Hash := sha256.New()
        sha256Hash.Write([]byte(message))
        sha256HashBytes := sha256Hash.Sum(nil)


        priv, _ := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
        pub := priv.PublicKey
        r, s, _ :=ecdsa.Sign(rand.Reader, priv, sha256HashBytes)
        signature := r.Bytes()
        signature = append(signature, s.Bytes()...)
        ecdsa.Verify(&pub, sha256HashBytes, r, s)
    }
}

func BenchmarkComputeChameleonHashScalarRand(b *testing.B){
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        scalarRand()
    }
}

func BenchmarkComputeChameleonHashPointRand(b *testing.B){
    b.ResetTimer()
    for i := b.N - 1; i >= 0; i-- {
        pointRand()
    }
}