/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: MIT License
*/

package main

import (
	"crypto/rand"
	"os"
	"runtime/debug"

	"github.com/czminami/ecdh"
	"github.com/op/go-logging"
)

var logger = logging.MustGetLogger("test")

func main() {
	format := logging.MustStringFormatter(`[%{module}] %{time:2006-01-02 15:04:05} [%{level}] [%{longpkg} %{shortfile}] { %{message} }`)

	backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
	backendConsole2Formatter := logging.NewBackendFormatter(backendConsole, format)

	logging.SetBackend(backendConsole2Formatter)
	logging.SetLevel(logging.INFO, "")

	defer func() {
		if err := recover(); err != nil {
			logger.Error(err)
			logger.Info(string(debug.Stack()))
		}
	}()

	Simplex()
	Duplex()
}

func Simplex() {
	// Suppose there are two people in A B;
	// A own pk_B;
	// B own sk_B;
	// A wants to send “Hello Word” to B in mode of ec-dh;
	// The following is an example.

	// B
	sk_B, pk_B, err := ecdh.EcdsaPKI(ecdh.P256, rand.Reader)
	if err != nil {
		logger.Error(err)
		return
	}

	/*  The following is A  */

	// A generate one temp keypair
	txSk_A, txPk_A, err := ecdh.EcdsaPKI(ecdh.P256, rand.Reader)
	if err != nil {
		logger.Error(err)
		return
	}

	// DH sk * pk, to get the intersection(x, y)
	X_A, Y_A := ecdh.DH_SP(txSk_A, pk_B)

	// A use intersection(x, y) to encrypt message
	encryptedMsg, err := ecdh.Encrypt(X_A.Bytes(), Y_A.Bytes(), nil, []byte("Hello Word"))
	if err != nil {
		logger.Error(err)
		return
	}

	// A just send txPk_A and encryptedMsg to B

	/*  The following is B  */

	// DH pk * sk, to get the intersection(x, y)
	X_B, Y_B := ecdh.DH_PS(txPk_A, sk_B)

	// B use intersection(x, y) to decrypt message
	message, err := ecdh.Decrypt(X_B.Bytes(), Y_B.Bytes(), nil, encryptedMsg)
	if err != nil {
		logger.Error(err)
		return
	}

	logger.Info("Simplex:", string(message))
}

func Duplex() {
	// Suppose there are two people in A B;
	// A own sk_A and pk_B;
	// B own sk_B and pk_A;
	// A wants to send “Hello Word” to B in mode of ec-dh;
	// The exchange will use one temp keypair in order to
	// avoid leaking confidentiality;
	// The following is an example.

	// A
	sk_A, pk_A, err := ecdh.EcdsaPKI(ecdh.P256, rand.Reader)
	if err != nil {
		logger.Error(err)
		return
	}

	// B
	sk_B, pk_B, err := ecdh.EcdsaPKI(ecdh.P256, rand.Reader)
	if err != nil {
		logger.Error(err)
		return
	}

	/*  The following is A  */

	// A get one random point K
	K, err := ecdh.K_Point(ecdh.P512, rand.Reader)
	if err != nil {
		logger.Error(err)
		return
	}

	// A make one temp txSk from sk_A by random point K
	txSk := ecdh.DerivedSk(sk_A, K)

	// DH sk * pk, to get the intersection(x, y)
	X_A, Y_A := ecdh.DH_SP(txSk, pk_B)

	// A use intersection(x, y) and k to encrypt message
	encryptedMsg, err := ecdh.Encrypt(X_A.Bytes(), Y_A.Bytes(), K, []byte("Hello Word"))
	if err != nil {
		logger.Error(err)
		return
	}

	// A just send K and encryptedMsg to B

	/*  The following is B  */

	// B make the temp txPk by pk_A and K
	txPk := ecdh.DerivedPk(pk_A, K)

	// DH pk * sk, to get the intersection(x, y)
	X_B, Y_B := ecdh.DH_PS(txPk, sk_B)

	// B use intersection(x, y) and k to decrypt message
	message, err := ecdh.Decrypt(X_B.Bytes(), Y_B.Bytes(), K, encryptedMsg)
	if err != nil {
		logger.Error(err)
		return
	}

	logger.Info("Duplex:", string(message))
}
