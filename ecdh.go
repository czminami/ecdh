/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: MIT License
*/

package ecdh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type Level uint

const (
	P244 Level = 244
	P256 Level = 256
	P384 Level = 384
	P512 Level = 512
)

var (
	hashFunc = sha3.New512
)

func EcdsaPKI(level Level, rander io.Reader) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var curve elliptic.Curve

	switch level {
	case P244:
		curve = elliptic.P224()

	case P256:
		curve = elliptic.P256()

	case P384:
		curve = elliptic.P384()

	case P512:
		curve = elliptic.P521()
	}

	sk, err := ecdsa.GenerateKey(curve, rander)
	if err != nil {
		return nil, nil, err
	}

	return sk, &sk.PublicKey, nil
}

func K_Point(level Level, rander io.Reader) ([]byte, error) {
	K := make([]byte, level)

	if _, err := io.ReadFull(rander, K); err != nil {
		return nil, err
	}

	return K, nil
}

func DerivedSk(sk *ecdsa.PrivateKey, K []byte) *ecdsa.PrivateKey {
	txSk := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: sk.Curve,
			X:     new(big.Int),
			Y:     new(big.Int),
		},
		D: new(big.Int),
	}

	txSk.D.Add(sk.D, new(big.Int).SetBytes(K))
	txSk.D.Mod(txSk.D, sk.PublicKey.Params().N)

	return txSk
}

func DerivedPk(pk *ecdsa.PublicKey, K []byte) *ecdsa.PublicKey {
	tmpX, tmpY := pk.ScalarBaseMult(K)
	txX, txY := pk.Curve.Add(pk.X, pk.Y, tmpX, tmpY)

	txPk := &ecdsa.PublicKey{Curve: pk.Curve, X: txX, Y: txY}

	return txPk
}

func DH_SP(sk *ecdsa.PrivateKey, txPk *ecdsa.PublicKey) (*big.Int, *big.Int) {
	return sk.Curve.ScalarMult(txPk.X, txPk.Y, sk.D.Bytes())
}

func DH_PS(pk *ecdsa.PublicKey, txSk *ecdsa.PrivateKey) (*big.Int, *big.Int) {
	return pk.Curve.ScalarMult(pk.X, pk.Y, txSk.D.Bytes())
}

func Encrypt(x, y, k []byte, messge []byte) ([]byte, error) {
	rander := hkdf.New(hashFunc, x, y, k)

	key := make([]byte, 32)
	if _, err := io.ReadFull(rander, key); err != nil {
		return nil, err
	}

	raw, err := AecEncrypt([][]byte{key}, messge)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func Decrypt(x, y, k []byte, encrypted []byte) ([]byte, error) {
	rander := hkdf.New(hashFunc, x, y, k)

	key := make([]byte, 32)
	if _, err := io.ReadFull(rander, key); err != nil {
		return nil, err
	}

	raw, err := AesDecrypt([][]byte{key}, encrypted)
	if err != nil {
		return nil, err
	}

	return raw, nil
}
