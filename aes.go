/*
Copyright github.com/czminami. All Rights Reserved.
SPDX-License-Identifier: MIT License
*/

package ecdh

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/hkdf"
)

func AecEncrypt(encKeys [][]byte, raw []byte) ([]byte, error) {
	for _, key := range encKeys {
		nonce := make([]byte, 12)
		additation := make([]byte, 32)

		kdf := hkdf.New(hashFunc, key, nil, nil)

		if _, err := kdf.Read(nonce); err != nil {
			return nil, err

		} else if _, err := kdf.Read(additation); err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		raw = aead.Seal(nil, nonce, raw, additation)
	}
	return raw, nil
}

func AesDecrypt(encKeys [][]byte, raw []byte) ([]byte, error) {
	for k := len(encKeys) - 1; k > -1; k-- {
		key := encKeys[k]

		nonce := make([]byte, 12)
		additation := make([]byte, 32)

		kdf := hkdf.New(hashFunc, key, nil, nil)

		if _, err := kdf.Read(nonce); err != nil {
			return nil, err

		} else if _, err := kdf.Read(additation); err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		raw, err = aead.Open(nil, nonce, raw, additation)
		if err != nil {
			return nil, err
		}
	}
	return raw, nil
}
