﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;


	/*
	* Reference implementation of DSTU7624 national Ukrainian standard of block encryption.
	* Thanks to Roman Oliynikov' native C implementation:
	* https://github.com/Roman-Oliynikov/Kalyna-reference
	*
	* DSTU7564 is very similar to AES but with some security improvements in key schedule algorithm
	* and supports different block and key lengths (128/256/512 bits).
	*/
	public class DSTU7624Engine : BlockCipher
	{
		private ulong[] internalState;
		private ulong[] workingKey;
		private ulong[][] roundKeys;

		/* Number of 64-bit words in block */
		private int wordsInBlock;

		/* Number of 64-bit words in key */
		private int wordsInKey;

		/* Number of encryption rounds depending on key length */
		private const int ROUNDS_128 = 10;
		private const int ROUNDS_256 = 14;
		private const int ROUNDS_512 = 18;

		private int roundsAmount;

		private bool forEncryption;

		public DSTU7624Engine(int blockBitLength)
		{
			/* DSTU7624 supports 128 | 256 | 512 key/block sizes */
			if (blockBitLength != 128 && blockBitLength != 256 && blockBitLength != 512)
			{
				throw new IllegalArgumentException("unsupported block length: only 128/256/512 are allowed");
			}

			wordsInBlock = (int)((uint)blockBitLength >> 6);
			internalState = new ulong[wordsInBlock];
		}

		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (!(@params is KeyParameter))
			{
				throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Engine init");
			}

			this.forEncryption = forEncryption;

			byte[] keyBytes = ((KeyParameter)@params).getKey();
			int keyBitLength = keyBytes.Length << 3;
			int blockBitLength = wordsInBlock << 6;

			if (keyBitLength != 128 && keyBitLength != 256 && keyBitLength != 512)
			{
				throw new IllegalArgumentException("unsupported key length: only 128/256/512 are allowed");
			}

			/* Limitations on key lengths depending on block lengths. See table 6.1 in standard */
			if (keyBitLength != blockBitLength && keyBitLength != (2 * blockBitLength))
			{
				throw new IllegalArgumentException("Unsupported key length");
			}

			switch (keyBitLength)
			{
			case 128:
				roundsAmount = ROUNDS_128;
				break;
			case 256:
				roundsAmount = ROUNDS_256;
				break;
			case 512:
				roundsAmount = ROUNDS_512;
				break;
			}

			wordsInKey = (int)((uint)keyBitLength >> 6);

			/* +1 round key as defined in standard */
			roundKeys = new ulong[roundsAmount + 1][];
			for (int roundKeyIndex = 0; roundKeyIndex < roundKeys.Length; roundKeyIndex++)
			{
				roundKeys[roundKeyIndex] = new ulong[wordsInBlock];
			}

			workingKey = new ulong[wordsInKey];

			if (keyBytes.Length != ((int)((uint)keyBitLength >> 3)))
			{
				throw new IllegalArgumentException("Invalid key parameter passed to DSTU7624Engine init");
			}

			/* Unpack encryption key bytes to words */
			Pack.littleEndianToULong(keyBytes, 0, workingKey);

			ulong[] tempKeys = new ulong[wordsInBlock];

			/* KSA in DSTU7624 is strengthened to mitigate known weaknesses in AES KSA (eprint.iacr.org/2012/260.pdf) */
			workingKeyExpandKT(workingKey, tempKeys);
			workingKeyExpandEven(workingKey, tempKeys);
			workingKeyExpandOdd();
		}

		public virtual string getAlgorithmName()
		{
			return "DSTU7624";
		}

		public virtual int getBlockSize()
		{
			return wordsInBlock << 3;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("DSTU7624Engine not initialised");
			}

			if (inOff + getBlockSize() > @in.Length)
			{
				throw new DataLengthException("Input buffer too short");
			}

			if (outOff + getBlockSize() > @out.Length)
			{
				throw new OutputLengthException("Output buffer too short");
			}

			if (forEncryption)
			{
				/* Encrypt */
				switch (wordsInBlock)
				{
				case 2:
				{
					encryptBlock_128(@in, inOff, @out, outOff);
					break;
				}
				default:
				{
					Pack.littleEndianToULong(@in, inOff, internalState);
					addRoundKey(0);
					for (int round = 0;;)
					{
						subBytes();
						shiftRows();
						mixColumns();

						if (++round == roundsAmount)
						{
							break;
						}

						xorRoundKey(round);
					}
					addRoundKey(roundsAmount);
					Pack.UlongToLittleEndian(internalState, @out, outOff);
					break;
				}
				}
			}
			else
			{
				/* Decrypt */
				switch (wordsInBlock)
				{
				case 2:
				{
					decryptBlock_128(@in, inOff, @out, outOff);
					break;
				}
				default:
				{
					Pack.littleEndianToULong(@in, inOff, internalState);
					subRoundKey(roundsAmount);
					for (int round = roundsAmount;;)
					{
						mixColumnsInv();
						invShiftRows();
						invSubBytes();

						if (--round == 0)
						{
							break;
						}

						xorRoundKey(round);
					}
					subRoundKey(0);
					Pack.UlongToLittleEndian(internalState, @out, outOff);
					break;
				}
				}
			}

			return getBlockSize();
		}

		public virtual void reset()
		{
			Arrays.fill(internalState, 0);
		}

		private void addRoundKey(int round)
		{
			ulong[] roundKey = roundKeys[round];
			for (int i = 0; i < wordsInBlock; ++i)
			{
				internalState[i] += roundKey[i];
			}
		}

		private void subRoundKey(int round)
		{
			ulong[] roundKey = roundKeys[round];
			for (int i = 0; i < wordsInBlock; ++i)
			{
				internalState[i] -= roundKey[i];
			}
		}

		private void xorRoundKey(int round)
		{
			ulong[] roundKey = roundKeys[round];
			for (int i = 0; i < wordsInBlock; ++i)
			{
				internalState[i] ^= roundKey[i];
			}
		}

		private void workingKeyExpandKT(ulong[] workingKey, ulong[] tempKeys)
		{
			ulong[] k0 = new ulong[wordsInBlock];
			ulong[] k1 = new ulong[wordsInBlock];

			internalState = new ulong[wordsInBlock];
			internalState[0] += (ulong)(wordsInBlock + wordsInKey + 1);

			if (wordsInBlock == wordsInKey)
			{
				JavaSystem.arraycopy(workingKey, 0, k0, 0, k0.Length);
				JavaSystem.arraycopy(workingKey, 0, k1, 0, k1.Length);
			}
			else
			{
				JavaSystem.arraycopy(workingKey, 0, k0, 0, wordsInBlock);
				JavaSystem.arraycopy(workingKey, wordsInBlock, k1, 0, wordsInBlock);
			}


			for (int wordIndex = 0; wordIndex < internalState.Length; wordIndex++)
			{
				internalState[wordIndex] += k0[wordIndex];
			}

			subBytes();
			shiftRows();
			mixColumns();

			for (int wordIndex = 0; wordIndex < internalState.Length; wordIndex++)
			{
				internalState[wordIndex] ^= k1[wordIndex];
			}

			subBytes();
			shiftRows();
			mixColumns();

			for (int wordIndex = 0; wordIndex < internalState.Length; wordIndex++)
			{
				internalState[wordIndex] += k0[wordIndex];
			}

			subBytes();
			shiftRows();
			mixColumns();

			JavaSystem.arraycopy(internalState, 0, tempKeys, 0, wordsInBlock);
		}

		private void workingKeyExpandEven(ulong[] workingKey, ulong[] tempKey)
		{
			ulong[] initialData = new ulong[wordsInKey];
			ulong[] tempRoundKey = new ulong[wordsInBlock];

			int round = 0;

			JavaSystem.arraycopy(workingKey, 0, initialData, 0, wordsInKey);

			ulong tmv = 0x0001000100010001L;

			while (true)
			{
				for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
				{
					tempRoundKey[wordIndex] = tempKey[wordIndex] + tmv;
				}

				for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
				{
					internalState[wordIndex] = initialData[wordIndex] + tempRoundKey[wordIndex];
				}

				subBytes();
				shiftRows();
				mixColumns();

				for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
				{
					internalState[wordIndex] ^= tempRoundKey[wordIndex];
				}

				subBytes();
				shiftRows();
				mixColumns();

				for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
				{
					internalState[wordIndex] += tempRoundKey[wordIndex];
				}

				JavaSystem.arraycopy(internalState, 0, roundKeys[round], 0, wordsInBlock);

				if (roundsAmount == round)
				{
					break;
				}

				if (wordsInBlock != wordsInKey)
				{
					round += 2;
					tmv <<= 1;

					for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
					{
						tempRoundKey[wordIndex] = tempKey[wordIndex] + tmv;
					}

					for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
					{
						internalState[wordIndex] = initialData[wordsInBlock + wordIndex] + tempRoundKey[wordIndex];
					}

					subBytes();
					shiftRows();
					mixColumns();

					for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
					{
						internalState[wordIndex] ^= tempRoundKey[wordIndex];
					}

					subBytes();
					shiftRows();
					mixColumns();

					for (int wordIndex = 0; wordIndex < wordsInBlock; wordIndex++)
					{
						internalState[wordIndex] += tempRoundKey[wordIndex];
					}

					JavaSystem.arraycopy(internalState, 0, roundKeys[round], 0, wordsInBlock);

					if (roundsAmount == round)
					{
						break;
					}
				}

				round += 2;
				tmv <<= 1;

				ulong temp = initialData[0];
				for (int i = 1; i < initialData.Length; ++i)
				{
					initialData[i - 1] = initialData[i];
				}
				initialData[initialData.Length - 1] = temp;
			}
		}

		private void workingKeyExpandOdd()
		{
			for (int roundIndex = 1; roundIndex < roundsAmount; roundIndex += 2)
			{
				rotateLeft(roundKeys[roundIndex - 1], roundKeys[roundIndex]);
			}
		}

		private void decryptBlock_128(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			ulong c0 = Pack.littleEndianToULong(@in, inOff);
			ulong c1 = Pack.littleEndianToULong(@in, inOff + 8);

			ulong[] roundKey = roundKeys[roundsAmount];
			c0 -= roundKey[0];
			c1 -= roundKey[1];

			for (int round = roundsAmount;;)
			{
				c0 = mixColumnInv(c0);
				c1 = mixColumnInv(c1);

				int lo0 = (int)c0, hi0 = (int)((long)((ulong)c0 >> 32));
				int lo1 = (int)c1, hi1 = (int)((long)((ulong)c1 >> 32));

				{
					byte t0 = T0[lo0 & 0xFF];
					byte t1 = T1[((int)((uint)lo0 >> 8)) & 0xFF];
					byte t2 = T2[((int)((uint)lo0 >> 16)) & 0xFF];
					byte t3 = T3[(int)((uint)lo0 >> 24)];
					lo0 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
					byte t4 = T0[hi1 & 0xFF];
					byte t5 = T1[((int)((uint)hi1 >> 8)) & 0xFF];
					byte t6 = T2[((int)((uint)hi1 >> 16)) & 0xFF];
					byte t7 = T3[(int)((uint)hi1 >> 24)];
					hi1 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
				    c0 = (ulong)lo0 | ((ulong)hi1 << 32);
                }

				{
					byte t0 = T0[lo1 & 0xFF];
					byte t1 = T1[((int)((uint)lo1 >> 8)) & 0xFF];
					byte t2 = T2[((int)((uint)lo1 >> 16)) & 0xFF];
					byte t3 = T3[(int)((uint)lo1 >> 24)];
					lo1 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
					byte t4 = T0[hi0 & 0xFF];
					byte t5 = T1[((int)((uint)hi0 >> 8)) & 0xFF];
					byte t6 = T2[((int)((uint)hi0 >> 16)) & 0xFF];
					byte t7 = T3[(int)((uint)hi0 >> 24)];
					hi0 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
				    c1 = (ulong)lo1 | ((ulong)hi0 << 32);
                }

				if (--round == 0)
				{
					break;
				}

				roundKey = roundKeys[round];
				c0 ^= roundKey[0];
				c1 ^= roundKey[1];
			}

			roundKey = roundKeys[0];
			c0 -= roundKey[0];
			c1 -= roundKey[1];

			Pack.UlongToLittleEndian(c0, @out, outOff);
			Pack.UlongToLittleEndian(c1, @out, outOff + 8);
		}

		private void encryptBlock_128(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			ulong c0 = Pack.littleEndianToULong(@in, inOff);
			ulong c1 = Pack.littleEndianToULong(@in, inOff + 8);

			ulong[] roundKey = roundKeys[0];
			c0 += roundKey[0];
			c1 += roundKey[1];

			for (int round = 0;;)
			{
				int lo0 = (int)c0, hi0 = (int)((long)((ulong)c0 >> 32));
				int lo1 = (int)c1, hi1 = (int)((long)((ulong)c1 >> 32));

				{
					byte t0 = S0[lo0 & 0xFF];
					byte t1 = S1[((int)((uint)lo0 >> 8)) & 0xFF];
					byte t2 = S2[((int)((uint)lo0 >> 16)) & 0xFF];
					byte t3 = S3[(int)((uint)lo0 >> 24)];
					lo0 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
					byte t4 = S0[hi1 & 0xFF];
					byte t5 = S1[((int)((uint)hi1 >> 8)) & 0xFF];
					byte t6 = S2[((int)((uint)hi1 >> 16)) & 0xFF];
					byte t7 = S3[(int)((uint)hi1 >> 24)];
					hi1 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
				    c0 = (ulong)lo0 | ((ulong)hi1 << 32);
                }

				{
					byte t0 = S0[lo1 & 0xFF];
					byte t1 = S1[((int)((uint)lo1 >> 8)) & 0xFF];
					byte t2 = S2[((int)((uint)lo1 >> 16)) & 0xFF];
					byte t3 = S3[(int)((uint)lo1 >> 24)];
					lo1 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
					byte t4 = S0[hi0 & 0xFF];
					byte t5 = S1[((int)((uint)hi0 >> 8)) & 0xFF];
					byte t6 = S2[((int)((uint)hi0 >> 16)) & 0xFF];
					byte t7 = S3[(int)((uint)hi0 >> 24)];
					hi0 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
				    c1 = (ulong)lo1 | ((ulong)hi0 << 32);
                }

				c0 = mixColumn(c0);
				c1 = mixColumn(c1);

				if (++round == roundsAmount)
				{
					break;
				}

				roundKey = roundKeys[round];
				c0 ^= roundKey[0];
				c1 ^= roundKey[1];
			}

			roundKey = roundKeys[roundsAmount];
			c0 += roundKey[0];
			c1 += roundKey[1];

			Pack.UlongToLittleEndian(c0, @out, outOff);
			Pack.UlongToLittleEndian(c1, @out, outOff + 8);
		}

		private void subBytes()
		{
			for (int i = 0; i < wordsInBlock; i++)
			{
				ulong u = internalState[i];
				int lo = (int)u, hi = (int)((long)((ulong)u >> 32));
				byte t0 = S0[lo & 0xFF];
				byte t1 = S1[((int)((uint)lo >> 8)) & 0xFF];
				byte t2 = S2[((int)((uint)lo >> 16)) & 0xFF];
				byte t3 = S3[(int)((uint)lo >> 24)];
				lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
				byte t4 = S0[hi & 0xFF];
				byte t5 = S1[((int)((uint)hi >> 8)) & 0xFF];
				byte t6 = S2[((int)((uint)hi >> 16)) & 0xFF];
				byte t7 = S3[(int)((uint)hi >> 24)];
				hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
			    internalState[i] = (ulong)lo | ((ulong)hi << 32);
            }
		}

		private void invSubBytes()
		{
			for (int i = 0; i < wordsInBlock; i++)
			{
				ulong u = internalState[i];
				int lo = (int)u, hi = (int)((long)((ulong)u >> 32));
				byte t0 = T0[lo & 0xFF];
				byte t1 = T1[((int)((uint)lo >> 8)) & 0xFF];
				byte t2 = T2[((int)((uint)lo >> 16)) & 0xFF];
				byte t3 = T3[(int)((uint)lo >> 24)];
				lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | ((int)t3 << 24);
				byte t4 = T0[hi & 0xFF];
				byte t5 = T1[((int)((uint)hi >> 8)) & 0xFF];
				byte t6 = T2[((int)((uint)hi >> 16)) & 0xFF];
				byte t7 = T3[(int)((uint)hi >> 24)];
				hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | ((int)t7 << 24);
				internalState[i] = (ulong)lo | ((ulong)hi << 32);
			}
		}

		private void shiftRows()
		{
			switch (wordsInBlock)
			{
			case 2:
			{
				ulong c0 = internalState[0], c1 = internalState[1];
				ulong d;

				d = (c0 ^ c1) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c1 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				break;
			}
			case 4:
			{
				ulong c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
				ulong d;

				d = (c0 ^ c2) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x0000FFFFFFFF0000UL;
				c1 ^= d;
				c3 ^= d;

				d = (c0 ^ c1) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c2 ^= d;
				c3 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				internalState[2] = c2;
				internalState[3] = c3;
				break;
			}
			case 8:
			{
				ulong c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
				ulong c4 = internalState[4], c5 = internalState[5], c6 = internalState[6], c7 = internalState[7];
				ulong d;

				d = (c0 ^ c4) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c4 ^= d;
				d = (c1 ^ c5) & 0x00FFFFFFFF000000UL;
				c1 ^= d;
				c5 ^= d;
				d = (c2 ^ c6) & 0x0000FFFFFFFF0000UL;
				c2 ^= d;
				c6 ^= d;
				d = (c3 ^ c7) & 0x000000FFFFFFFF00UL;
				c3 ^= d;
				c7 ^= d;

				d = (c0 ^ c2) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x00FFFF0000FFFF00UL;
				c1 ^= d;
				c3 ^= d;
				d = (c4 ^ c6) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c4 ^= d;
				c6 ^= d;
				d = (c5 ^ c7) & 0x00FFFF0000FFFF00UL;
				c5 ^= d;
				c7 ^= d;

				d = (c0 ^ c1) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c2 ^= d;
				c3 ^= d;
				d = (c4 ^ c5) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c4 ^= d;
				c5 ^= d;
				d = (c6 ^ c7) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c6 ^= d;
				c7 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				internalState[2] = c2;
				internalState[3] = c3;
				internalState[4] = c4;
				internalState[5] = c5;
				internalState[6] = c6;
				internalState[7] = c7;
				break;
			}
			default:
			{
				throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
			}
			}
		}

		private void invShiftRows()
		{
			switch (wordsInBlock)
			{
			case 2:
			{
				ulong c0 = internalState[0], c1 = internalState[1];
				ulong d;

				d = (c0 ^ c1) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c1 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				break;
			}
			case 4:
			{
				ulong c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
				ulong d;

				d = (c0 ^ c1) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c2 ^= d;
				c3 ^= d;

				d = (c0 ^ c2) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x0000FFFFFFFF0000L;
				c1 ^= d;
				c3 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				internalState[2] = c2;
				internalState[3] = c3;
				break;
			}
			case 8:
			{
				ulong c0 = internalState[0], c1 = internalState[1], c2 = internalState[2], c3 = internalState[3];
				ulong c4 = internalState[4], c5 = internalState[5], c6 = internalState[6], c7 = internalState[7];
				ulong d;

				d = (c0 ^ c1) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c2 ^= d;
				c3 ^= d;
				d = (c4 ^ c5) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c4 ^= d;
				c5 ^= d;
				d = (c6 ^ c7) & unchecked((ulong)0xFF00FF00FF00FF00UL);
				c6 ^= d;
				c7 ^= d;

				d = (c0 ^ c2) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x00FFFF0000FFFF00UL;
				c1 ^= d;
				c3 ^= d;
				d = (c4 ^ c6) & unchecked((ulong)0xFFFF0000FFFF0000UL);
				c4 ^= d;
				c6 ^= d;
				d = (c5 ^ c7) & 0x00FFFF0000FFFF00UL;
				c5 ^= d;
				c7 ^= d;

				d = (c0 ^ c4) & unchecked((ulong)0xFFFFFFFF00000000UL);
				c0 ^= d;
				c4 ^= d;
				d = (c1 ^ c5) & 0x00FFFFFFFF000000UL;
				c1 ^= d;
				c5 ^= d;
				d = (c2 ^ c6) & 0x0000FFFFFFFF0000UL;
				c2 ^= d;
				c6 ^= d;
				d = (c3 ^ c7) & 0x000000FFFFFFFF00UL;
				c3 ^= d;
				c7 ^= d;

				internalState[0] = c0;
				internalState[1] = c1;
				internalState[2] = c2;
				internalState[3] = c3;
				internalState[4] = c4;
				internalState[5] = c5;
				internalState[6] = c6;
				internalState[7] = c7;
				break;
			}
			default:
			{
				throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
			}
			}
		}

		private static ulong mixColumn(ulong c)
		{
	//        // Calculate column multiplied by powers of 'x'
	//        long x0 = c;
	//        long x1 = mulX(x0);
	//        long x2 = mulX(x1);
	//        long x3 = mulX(x2);
	//
	//        // Calculate products with circulant matrix from (0x01, 0x01, 0x05, 0x01, 0x08, 0x06, 0x07, 0x04)
	//        long m0 = x0;
	//        long m1 = x0;
	//        long m2 = x0 ^ x2;
	//        long m3 = x0;
	//        long m4 = x3;
	//        long m5 = x1 ^ x2;
	//        long m6 = x0 ^ x1 ^ x2;
	//        long m7 = x2;
	//
	//        // Assemble the rotated products
	//        return m0
	//            ^ rotate(8, m1)
	//            ^ rotate(16, m2)
	//            ^ rotate(24, m3)
	//            ^ rotate(32, m4)
	//            ^ rotate(40, m5)
	//            ^ rotate(48, m6)
	//            ^ rotate(56, m7);

			ulong x1 = mulX(c);
			ulong u, v;

			u = rotate(8, c) ^ c;
			u ^= rotate(16, u);
			u ^= rotate(48, c);

			v = mulX2(u ^ c ^ x1);

			return u ^ rotate(32, v) ^ rotate(40, x1) ^ rotate(48, x1);
		}

		private void mixColumns()
		{
			for (int col = 0; col < wordsInBlock; ++col)
			{
				internalState[col] = mixColumn(internalState[col]);
			}
		}

		private static ulong mixColumnInv(ulong c)
		{
	/*
	        // Calculate column multiplied by powers of 'x'
	        long x0 = c;
	        long x1 = mulX(x0);
	        long x2 = mulX(x1);
	        long x3 = mulX(x2);
	        long x4 = mulX(x3);
	        long x5 = mulX(x4);
	        long x6 = mulX(x5);
	        long x7 = mulX(x6);
	
	        // Calculate products with circulant matrix from (0xAD,0x95,0x76,0xA8,0x2F,0x49,0xD7,0xCA)
	//        long m0 = x0 ^ x2 ^ x3 ^ x5 ^ x7;
	//        long m1 = x0 ^ x2 ^ x4 ^ x7;
	//        long m2 = x1 ^ x2 ^ x4 ^ x5 ^ x6;
	//        long m3 = x3 ^ x5 ^ x7;
	//        long m4 = x0 ^ x1 ^ x2 ^ x3 ^ x5;
	//        long m5 = x0 ^ x3 ^ x6;
	//        long m6 = x0 ^ x1 ^ x2 ^ x4 ^ x6 ^ x7;
	//        long m7 = x1 ^ x3 ^ x6 ^ x7;
	
	        long m5 = x0 ^ x3 ^ x6;
	        x0 ^= x2;
	        long m3 = x3 ^ x5 ^ x7;
	        long m0 = m3 ^ x0;
	        long m6 = x0 ^ x4;
	        long m1 = m6 ^ x7;
	        x5 ^= x1;
	        x7 ^= x1 ^ x6;
	        long m2 = x2 ^ x4 ^ x5 ^ x6;
	        long m4 = x0 ^ x3 ^ x5;
	        m6 ^= x7;
	        long m7 = x3 ^ x7;
	
	        // Assemble the rotated products
	        return m0
	            ^ rotate(8, m1)
	            ^ rotate(16, m2)
	            ^ rotate(24, m3)
	            ^ rotate(32, m4)
	            ^ rotate(40, m5)
	            ^ rotate(48, m6)
	            ^ rotate(56, m7);
	*/

			ulong u0 = c;
			u0 ^= rotate(8, u0);
			u0 ^= rotate(32, u0);
			u0 ^= rotate(48, c);

			ulong t = u0 ^ c;

			ulong c48 = rotate(48, c);
			ulong c56 = rotate(56, c);

			ulong u7 = t ^ c56;
			ulong u6 = rotate(56, t);
			u6 ^= mulX(u7);
			ulong u5 = rotate(16, t) ^ c;
			u5 ^= rotate(40, mulX(u6) ^ c);
			ulong u4 = t ^ c48;
			u4 ^= mulX(u5);
			ulong u3 = rotate(16, u0);
			u3 ^= mulX(u4);
			ulong u2 = t ^ rotate(24, c) ^ c48 ^ c56;
			u2 ^= mulX(u3);
			ulong u1 = rotate(32, t) ^ c ^ c56;
			u1 ^= mulX(u2);
			u0 ^= mulX(rotate(40, u1));

			return u0;
		}

		private void mixColumnsInv()
		{
			for (int col = 0; col < wordsInBlock; ++col)
			{
				internalState[col] = mixColumnInv(internalState[col]);
			}
		}

		private static ulong mulX(ulong n)
		{
		    return ((n & 0x7F7F7F7F7F7F7F7FUL) << 1) ^ (((n & 0x8080808080808080UL) >> 7) * 0x1DUL);
        }

		private static ulong mulX2(ulong n)
		{
		    return ((n & 0x3F3F3F3F3F3F3F3FUL) << 2) ^ (((n & 0x8080808080808080UL) >> 6) * 0x1DUL) ^ (((n & 0x4040404040404040UL) >> 6) * 0x1DUL);
        }

	//    private static long mulX4(long n)
	//    {
	//        long u = n & 0xF0F0F0F0F0F0F0F0L;
	//        return ((n & 0x0F0F0F0F0F0F0F0FL) << 4) ^ u ^ (u >>> 1) ^ (u >>> 2) ^ (u >>> 4);
	//    }

		/*
		 * Pair-wise modular multiplication of 8 byte-pairs.
		 * 
		 * REDUCTION_POLYNOMIAL is x^8 + x^4 + x^3 + x^2 + 1
		 */  
	//    private static long multiplyGFx8(long u, long v, int vMaxDegree)
	//    {
	//        long r = u & ((v & 0x0101010101010101L) * 0xFFL);
	//        for (int i = 1; i <= vMaxDegree; ++i)
	//        {
	//            u = ((u & 0x7F7F7F7F7F7F7F7FL) << 1) ^ (((u >>> 7) & 0x0101010101010101L) * 0x1DL);
	//            v >>>= 1;
	//
	//            r ^= u & ((v & 0x0101010101010101L) * 0xFFL);
	//        }
	//
	//        return r;
	//    }

	//    private static long multiplyMDS(long u)
	//    {
	//        long r = 0, s = 0, t = (u >>> 8);
	//        r ^= u & 0x0000001F00000000L; r <<= 1;
	//        s ^= t & 0x00000000E0000000L; s <<= 1;
	//        r ^= u & 0x3F3F3F00003F0000L; r <<= 1;
	//        s ^= t & 0x00C0C0C00000C000L; s <<= 1;
	//        r ^= u & 0x007F7F0000000000L; r <<= 1;
	//        s ^= t & 0x0000808000000000L; s <<= 1;
	//        r ^= u & 0x00FF0000FFFFFFFFL;
	//        r ^= s ^ (s << 2) ^ (s << 3) ^ (s << 4);
	//        return r;
	//    }

		private static ulong rotate(int n, ulong x)
		{
			return ((ulong)((ulong)x >> n)) | (x << -n);
		}

		private void rotateLeft(ulong[] x, ulong[] z)
		{
			switch (wordsInBlock)
			{
			case 2:
			{
				ulong x0 = x[0], x1 = x[1];
				z[0] = ((ulong)((ulong)x0 >> 56)) | (x1 << 8);
				z[1] = ((ulong)((ulong)x1 >> 56)) | (x0 << 8);
				break;
			}
			case 4:
			{
				ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
				z[0] = ((ulong)((ulong)x1 >> 24)) | (x2 << 40);
				z[1] = ((ulong)((ulong)x2 >> 24)) | (x3 << 40);
				z[2] = ((ulong)((ulong)x3 >> 24)) | (x0 << 40);
				z[3] = ((ulong)((ulong)x0 >> 24)) | (x1 << 40);
				break;
			}
			case 8:
			{
				ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
				ulong x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
				z[0] = ((ulong)((ulong)x2 >> 24)) | (x3 << 40);
				z[1] = ((ulong)((ulong)x3 >> 24)) | (x4 << 40);
				z[2] = ((ulong)((ulong)x4 >> 24)) | (x5 << 40);
				z[3] = ((ulong)((ulong)x5 >> 24)) | (x6 << 40);
				z[4] = ((ulong)((ulong)x6 >> 24)) | (x7 << 40);
				z[5] = ((ulong)((ulong)x7 >> 24)) | (x0 << 40);
				z[6] = ((ulong)((ulong)x0 >> 24)) | (x1 << 40);
				z[7] = ((ulong)((ulong)x1 >> 24)) | (x2 << 40);
				break;
			}
			default:
			{
				throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
			}
			}
		}

	//    private static final long mdsMatrix = 0x0407060801050101L;
	//    private static final long mdsInvMatrix = 0xCAD7492FA87695ADL;

		private static readonly byte[] S0 = new byte[]{unchecked((byte)0xa8), (byte)0x43, (byte)0x5f, (byte)0x06, (byte)0x6b, (byte)0x75, (byte)0x6c, (byte)0x59, (byte)0x71, unchecked((byte)0xdf), unchecked((byte)0x87), unchecked((byte)0x95), (byte)0x17, unchecked((byte)0xf0), unchecked((byte)0xd8), (byte)0x09, (byte)0x6d, unchecked((byte)0xf3), (byte)0x1d, unchecked((byte)0xcb), unchecked((byte)0xc9), (byte)0x4d, (byte)0x2c, unchecked((byte)0xaf), (byte)0x79, unchecked((byte)0xe0), unchecked((byte)0x97), unchecked((byte)0xfd), (byte)0x6f, (byte)0x4b, (byte)0x45, (byte)0x39, (byte)0x3e, unchecked((byte)0xdd), unchecked((byte)0xa3), (byte)0x4f, unchecked((byte)0xb4), unchecked((byte)0xb6), unchecked((byte)0x9a), (byte)0x0e, (byte)0x1f, unchecked((byte)0xbf), (byte)0x15, unchecked((byte)0xe1), (byte)0x49, unchecked((byte)0xd2), unchecked((byte)0x93), unchecked((byte)0xc6), unchecked((byte)0x92), (byte)0x72, unchecked((byte)0x9e), (byte)0x61, unchecked((byte)0xd1), (byte)0x63, unchecked((byte)0xfa), unchecked((byte)0xee), unchecked((byte)0xf4), (byte)0x19, unchecked((byte)0xd5), unchecked((byte)0xad), (byte)0x58, unchecked((byte)0xa4), unchecked((byte)0xbb), unchecked((byte)0xa1), unchecked((byte)0xdc), unchecked((byte)0xf2), unchecked((byte)0x83), (byte)0x37, (byte)0x42, unchecked((byte)0xe4), (byte)0x7a, (byte)0x32, unchecked((byte)0x9c), unchecked((byte)0xcc), unchecked((byte)0xab), (byte)0x4a, unchecked((byte)0x8f), (byte)0x6e, (byte)0x04, (byte)0x27, (byte)0x2e, unchecked((byte)0xe7), unchecked((byte)0xe2), (byte)0x5a, unchecked((byte)0x96), (byte)0x16, (byte)0x23, (byte)0x2b, unchecked((byte)0xc2), (byte)0x65, (byte)0x66, (byte)0x0f, unchecked((byte)0xbc), unchecked((byte)0xa9), (byte)0x47, (byte)0x41, (byte)0x34, (byte)0x48, unchecked((byte)0xfc), unchecked((byte)0xb7), (byte)0x6a, unchecked((byte)0x88), unchecked((byte)0xa5), (byte)0x53, unchecked((byte)0x86), unchecked((byte)0xf9), (byte)0x5b, unchecked((byte)0xdb), (byte)0x38, (byte)0x7b, unchecked((byte)0xc3), (byte)0x1e, (byte)0x22, (byte)0x33, (byte)0x24, (byte)0x28, (byte)0x36, unchecked((byte)0xc7), unchecked((byte)0xb2), (byte)0x3b, unchecked((byte)0x8e), (byte)0x77, unchecked((byte)0xba), unchecked((byte)0xf5), (byte)0x14, unchecked((byte)0x9f), (byte)0x08, (byte)0x55, unchecked((byte)0x9b), (byte)0x4c, unchecked((byte)0xfe), (byte)0x60, (byte)0x5c, unchecked((byte)0xda), (byte)0x18, (byte)0x46, unchecked((byte)0xcd), (byte)0x7d, (byte)0x21, unchecked((byte)0xb0), (byte)0x3f, (byte)0x1b, unchecked((byte)0x89), unchecked((byte)0xff), unchecked((byte)0xeb), unchecked((byte)0x84), (byte)0x69, (byte)0x3a, unchecked((byte)0x9d), unchecked((byte)0xd7), unchecked((byte)0xd3), (byte)0x70, (byte)0x67, (byte)0x40, unchecked((byte)0xb5), unchecked((byte)0xde), (byte)0x5d, (byte)0x30, unchecked((byte)0x91), unchecked((byte)0xb1), (byte)0x78, (byte)0x11, (byte)0x01, unchecked((byte)0xe5), (byte)0x00, (byte)0x68, unchecked((byte)0x98), unchecked((byte)0xa0), unchecked((byte)0xc5), (byte)0x02, unchecked((byte)0xa6), (byte)0x74, (byte)0x2d, (byte)0x0b, unchecked((byte)0xa2), (byte)0x76, unchecked((byte)0xb3), unchecked((byte)0xbe), unchecked((byte)0xce), unchecked((byte)0xbd), unchecked((byte)0xae), unchecked((byte)0xe9), unchecked((byte)0x8a), (byte)0x31, (byte)0x1c, unchecked((byte)0xec), unchecked((byte)0xf1), unchecked((byte)0x99), unchecked((byte)0x94), unchecked((byte)0xaa), unchecked((byte)0xf6), (byte)0x26, (byte)0x2f, unchecked((byte)0xef), unchecked((byte)0xe8), unchecked((byte)0x8c), (byte)0x35, (byte)0x03, unchecked((byte)0xd4), (byte)0x7f, unchecked((byte)0xfb), (byte)0x05, unchecked((byte)0xc1), (byte)0x5e, unchecked((byte)0x90), (byte)0x20, (byte)0x3d, unchecked((byte)0x82), unchecked((byte)0xf7), unchecked((byte)0xea), (byte)0x0a, (byte)0x0d, (byte)0x7e, unchecked((byte)0xf8), (byte)0x50, (byte)0x1a, unchecked((byte)0xc4), (byte)0x07, (byte)0x57, unchecked((byte)0xb8), (byte)0x3c, (byte)0x62, unchecked((byte)0xe3), unchecked((byte)0xc8), unchecked((byte)0xac), (byte)0x52, (byte)0x64, (byte)0x10, unchecked((byte)0xd0), unchecked((byte)0xd9), (byte)0x13, (byte)0x0c, (byte)0x12, (byte)0x29, (byte)0x51, unchecked((byte)0xb9), unchecked((byte)0xcf), unchecked((byte)0xd6), (byte)0x73, unchecked((byte)0x8d), unchecked((byte)0x81), (byte)0x54, unchecked((byte)0xc0), unchecked((byte)0xed), (byte)0x4e, (byte)0x44, unchecked((byte)0xa7), (byte)0x2a, unchecked((byte)0x85), (byte)0x25, unchecked((byte)0xe6), unchecked((byte)0xca), (byte)0x7c, unchecked((byte)0x8b), (byte)0x56, unchecked((byte)0x80)};

		private static readonly byte[] S1 = new byte[]{unchecked((byte)0xce), unchecked((byte)0xbb), unchecked((byte)0xeb), unchecked((byte)0x92), unchecked((byte)0xea), unchecked((byte)0xcb), (byte)0x13, unchecked((byte)0xc1), unchecked((byte)0xe9), (byte)0x3a, unchecked((byte)0xd6), unchecked((byte)0xb2), unchecked((byte)0xd2), unchecked((byte)0x90), (byte)0x17, unchecked((byte)0xf8), (byte)0x42, (byte)0x15, (byte)0x56, unchecked((byte)0xb4), (byte)0x65, (byte)0x1c, unchecked((byte)0x88), (byte)0x43, unchecked((byte)0xc5), (byte)0x5c, (byte)0x36, unchecked((byte)0xba), unchecked((byte)0xf5), (byte)0x57, (byte)0x67, unchecked((byte)0x8d), (byte)0x31, unchecked((byte)0xf6), (byte)0x64, (byte)0x58, unchecked((byte)0x9e), unchecked((byte)0xf4), (byte)0x22, unchecked((byte)0xaa), (byte)0x75, (byte)0x0f, (byte)0x02, unchecked((byte)0xb1), unchecked((byte)0xdf), (byte)0x6d, (byte)0x73, (byte)0x4d, (byte)0x7c, (byte)0x26, (byte)0x2e, unchecked((byte)0xf7), (byte)0x08, (byte)0x5d, (byte)0x44, (byte)0x3e, unchecked((byte)0x9f), (byte)0x14, unchecked((byte)0xc8), unchecked((byte)0xae), (byte)0x54, (byte)0x10, unchecked((byte)0xd8), unchecked((byte)0xbc), (byte)0x1a, (byte)0x6b, (byte)0x69, unchecked((byte)0xf3), unchecked((byte)0xbd), (byte)0x33, unchecked((byte)0xab), unchecked((byte)0xfa), unchecked((byte)0xd1), unchecked((byte)0x9b), (byte)0x68, (byte)0x4e, (byte)0x16, unchecked((byte)0x95), unchecked((byte)0x91), unchecked((byte)0xee), (byte)0x4c, (byte)0x63, unchecked((byte)0x8e), (byte)0x5b, unchecked((byte)0xcc), (byte)0x3c, (byte)0x19, unchecked((byte)0xa1), unchecked((byte)0x81), (byte)0x49, (byte)0x7b, unchecked((byte)0xd9), (byte)0x6f, (byte)0x37, (byte)0x60, unchecked((byte)0xca), unchecked((byte)0xe7), (byte)0x2b, (byte)0x48, unchecked((byte)0xfd), unchecked((byte)0x96), (byte)0x45, unchecked((byte)0xfc), (byte)0x41, (byte)0x12, (byte)0x0d, (byte)0x79, unchecked((byte)0xe5), unchecked((byte)0x89), unchecked((byte)0x8c), unchecked((byte)0xe3), (byte)0x20, (byte)0x30, unchecked((byte)0xdc), unchecked((byte)0xb7), (byte)0x6c, (byte)0x4a, unchecked((byte)0xb5), (byte)0x3f, unchecked((byte)0x97), unchecked((byte)0xd4), (byte)0x62, (byte)0x2d, (byte)0x06, unchecked((byte)0xa4), unchecked((byte)0xa5), unchecked((byte)0x83), (byte)0x5f, (byte)0x2a, unchecked((byte)0xda), unchecked((byte)0xc9), (byte)0x00, (byte)0x7e, unchecked((byte)0xa2), (byte)0x55, unchecked((byte)0xbf), (byte)0x11, unchecked((byte)0xd5), unchecked((byte)0x9c), unchecked((byte)0xcf), (byte)0x0e, (byte)0x0a, (byte)0x3d, (byte)0x51, (byte)0x7d, unchecked((byte)0x93), (byte)0x1b, unchecked((byte)0xfe), unchecked((byte)0xc4), (byte)0x47, (byte)0x09, unchecked((byte)0x86), (byte)0x0b, unchecked((byte)0x8f), unchecked((byte)0x9d), (byte)0x6a, (byte)0x07, unchecked((byte)0xb9), unchecked((byte)0xb0), unchecked((byte)0x98), (byte)0x18, (byte)0x32, (byte)0x71, (byte)0x4b, unchecked((byte)0xef), (byte)0x3b, (byte)0x70, unchecked((byte)0xa0), unchecked((byte)0xe4), (byte)0x40, unchecked((byte)0xff), unchecked((byte)0xc3), unchecked((byte)0xa9), unchecked((byte)0xe6), (byte)0x78, unchecked((byte)0xf9), unchecked((byte)0x8b), (byte)0x46, unchecked((byte)0x80), (byte)0x1e, (byte)0x38, unchecked((byte)0xe1), unchecked((byte)0xb8), unchecked((byte)0xa8), unchecked((byte)0xe0), (byte)0x0c, (byte)0x23, (byte)0x76, (byte)0x1d, (byte)0x25, (byte)0x24, (byte)0x05, unchecked((byte)0xf1), (byte)0x6e, unchecked((byte)0x94), (byte)0x28, unchecked((byte)0x9a), unchecked((byte)0x84), unchecked((byte)0xe8), unchecked((byte)0xa3), (byte)0x4f, (byte)0x77, unchecked((byte)0xd3), unchecked((byte)0x85), unchecked((byte)0xe2), (byte)0x52, unchecked((byte)0xf2), unchecked((byte)0x82), (byte)0x50, (byte)0x7a, (byte)0x2f, (byte)0x74, (byte)0x53, unchecked((byte)0xb3), (byte)0x61, unchecked((byte)0xaf), (byte)0x39, (byte)0x35, unchecked((byte)0xde), unchecked((byte)0xcd), (byte)0x1f, unchecked((byte)0x99), unchecked((byte)0xac), unchecked((byte)0xad), (byte)0x72, (byte)0x2c, unchecked((byte)0xdd), unchecked((byte)0xd0), unchecked((byte)0x87), unchecked((byte)0xbe), (byte)0x5e, unchecked((byte)0xa6), unchecked((byte)0xec), (byte)0x04, unchecked((byte)0xc6), (byte)0x03, (byte)0x34, unchecked((byte)0xfb), unchecked((byte)0xdb), (byte)0x59, unchecked((byte)0xb6), unchecked((byte)0xc2), (byte)0x01, unchecked((byte)0xf0), (byte)0x5a, unchecked((byte)0xed), unchecked((byte)0xa7), (byte)0x66, (byte)0x21, (byte)0x7f, unchecked((byte)0x8a), (byte)0x27, unchecked((byte)0xc7), unchecked((byte)0xc0), (byte)0x29, unchecked((byte)0xd7)};

		private static readonly byte[] S2 = new byte[]{unchecked((byte)0x93), unchecked((byte)0xd9), unchecked((byte)0x9a), unchecked((byte)0xb5), unchecked((byte)0x98), (byte)0x22, (byte)0x45, unchecked((byte)0xfc), unchecked((byte)0xba), (byte)0x6a, unchecked((byte)0xdf), (byte)0x02, unchecked((byte)0x9f), unchecked((byte)0xdc), (byte)0x51, (byte)0x59, (byte)0x4a, (byte)0x17, (byte)0x2b, unchecked((byte)0xc2), unchecked((byte)0x94), unchecked((byte)0xf4), unchecked((byte)0xbb), unchecked((byte)0xa3), (byte)0x62, unchecked((byte)0xe4), (byte)0x71, unchecked((byte)0xd4), unchecked((byte)0xcd), (byte)0x70, (byte)0x16, unchecked((byte)0xe1), (byte)0x49, (byte)0x3c, unchecked((byte)0xc0), unchecked((byte)0xd8), (byte)0x5c, unchecked((byte)0x9b), unchecked((byte)0xad), unchecked((byte)0x85), (byte)0x53, unchecked((byte)0xa1), (byte)0x7a, unchecked((byte)0xc8), (byte)0x2d, unchecked((byte)0xe0), unchecked((byte)0xd1), (byte)0x72, unchecked((byte)0xa6), (byte)0x2c, unchecked((byte)0xc4), unchecked((byte)0xe3), (byte)0x76, (byte)0x78, unchecked((byte)0xb7), unchecked((byte)0xb4), (byte)0x09, (byte)0x3b, (byte)0x0e, (byte)0x41, (byte)0x4c, unchecked((byte)0xde), unchecked((byte)0xb2), unchecked((byte)0x90), (byte)0x25, unchecked((byte)0xa5), unchecked((byte)0xd7), (byte)0x03, (byte)0x11, (byte)0x00, unchecked((byte)0xc3), (byte)0x2e, unchecked((byte)0x92), unchecked((byte)0xef), (byte)0x4e, (byte)0x12, unchecked((byte)0x9d), (byte)0x7d, unchecked((byte)0xcb), (byte)0x35, (byte)0x10, unchecked((byte)0xd5), (byte)0x4f, unchecked((byte)0x9e), (byte)0x4d, unchecked((byte)0xa9), (byte)0x55, unchecked((byte)0xc6), unchecked((byte)0xd0), (byte)0x7b, (byte)0x18, unchecked((byte)0x97), unchecked((byte)0xd3), (byte)0x36, unchecked((byte)0xe6), (byte)0x48, (byte)0x56, unchecked((byte)0x81), unchecked((byte)0x8f), (byte)0x77, unchecked((byte)0xcc), unchecked((byte)0x9c), unchecked((byte)0xb9), unchecked((byte)0xe2), unchecked((byte)0xac), unchecked((byte)0xb8), (byte)0x2f, (byte)0x15, unchecked((byte)0xa4), (byte)0x7c, unchecked((byte)0xda), (byte)0x38, (byte)0x1e, (byte)0x0b, (byte)0x05, unchecked((byte)0xd6), (byte)0x14, (byte)0x6e, (byte)0x6c, (byte)0x7e, (byte)0x66, unchecked((byte)0xfd), unchecked((byte)0xb1), unchecked((byte)0xe5), (byte)0x60, unchecked((byte)0xaf), (byte)0x5e, (byte)0x33, unchecked((byte)0x87), unchecked((byte)0xc9), unchecked((byte)0xf0), (byte)0x5d, (byte)0x6d, (byte)0x3f, unchecked((byte)0x88), unchecked((byte)0x8d), unchecked((byte)0xc7), unchecked((byte)0xf7), (byte)0x1d, unchecked((byte)0xe9), unchecked((byte)0xec), unchecked((byte)0xed), unchecked((byte)0x80), (byte)0x29, (byte)0x27, unchecked((byte)0xcf), unchecked((byte)0x99), unchecked((byte)0xa8), (byte)0x50, (byte)0x0f, (byte)0x37, (byte)0x24, (byte)0x28, (byte)0x30, unchecked((byte)0x95), unchecked((byte)0xd2), (byte)0x3e, (byte)0x5b, (byte)0x40, unchecked((byte)0x83), unchecked((byte)0xb3), (byte)0x69, (byte)0x57, (byte)0x1f, (byte)0x07, (byte)0x1c, unchecked((byte)0x8a), unchecked((byte)0xbc), (byte)0x20, unchecked((byte)0xeb), unchecked((byte)0xce), unchecked((byte)0x8e), unchecked((byte)0xab), unchecked((byte)0xee), (byte)0x31, unchecked((byte)0xa2), (byte)0x73, unchecked((byte)0xf9), unchecked((byte)0xca), (byte)0x3a, (byte)0x1a, unchecked((byte)0xfb), (byte)0x0d, unchecked((byte)0xc1), unchecked((byte)0xfe), unchecked((byte)0xfa), unchecked((byte)0xf2), (byte)0x6f, unchecked((byte)0xbd), unchecked((byte)0x96), unchecked((byte)0xdd), (byte)0x43, (byte)0x52, unchecked((byte)0xb6), (byte)0x08, unchecked((byte)0xf3), unchecked((byte)0xae), unchecked((byte)0xbe), (byte)0x19, unchecked((byte)0x89), (byte)0x32, (byte)0x26, unchecked((byte)0xb0), unchecked((byte)0xea), (byte)0x4b, (byte)0x64, unchecked((byte)0x84), unchecked((byte)0x82), (byte)0x6b, unchecked((byte)0xf5), (byte)0x79, unchecked((byte)0xbf), (byte)0x01, (byte)0x5f, (byte)0x75, (byte)0x63, (byte)0x1b, (byte)0x23, (byte)0x3d, (byte)0x68, (byte)0x2a, (byte)0x65, unchecked((byte)0xe8), unchecked((byte)0x91), unchecked((byte)0xf6), unchecked((byte)0xff), (byte)0x13, (byte)0x58, unchecked((byte)0xf1), (byte)0x47, (byte)0x0a, (byte)0x7f, unchecked((byte)0xc5), unchecked((byte)0xa7), unchecked((byte)0xe7), (byte)0x61, (byte)0x5a, (byte)0x06, (byte)0x46, (byte)0x44, (byte)0x42, (byte)0x04, unchecked((byte)0xa0), unchecked((byte)0xdb), (byte)0x39, unchecked((byte)0x86), (byte)0x54, unchecked((byte)0xaa), unchecked((byte)0x8c), (byte)0x34, (byte)0x21, unchecked((byte)0x8b), unchecked((byte)0xf8), (byte)0x0c, (byte)0x74, (byte)0x67};

		private static readonly byte[] S3 = new byte[]{(byte)0x68, unchecked((byte)0x8d), unchecked((byte)0xca), (byte)0x4d, (byte)0x73, (byte)0x4b, (byte)0x4e, (byte)0x2a, unchecked((byte)0xd4), (byte)0x52, (byte)0x26, unchecked((byte)0xb3), (byte)0x54, (byte)0x1e, (byte)0x19, (byte)0x1f, (byte)0x22, (byte)0x03, (byte)0x46, (byte)0x3d, (byte)0x2d, (byte)0x4a, (byte)0x53, unchecked((byte)0x83), (byte)0x13, unchecked((byte)0x8a), unchecked((byte)0xb7), unchecked((byte)0xd5), (byte)0x25, (byte)0x79, unchecked((byte)0xf5), unchecked((byte)0xbd), (byte)0x58, (byte)0x2f, (byte)0x0d, (byte)0x02, unchecked((byte)0xed), (byte)0x51, unchecked((byte)0x9e), (byte)0x11, unchecked((byte)0xf2), (byte)0x3e, (byte)0x55, (byte)0x5e, unchecked((byte)0xd1), (byte)0x16, (byte)0x3c, (byte)0x66, (byte)0x70, (byte)0x5d, unchecked((byte)0xf3), (byte)0x45, (byte)0x40, unchecked((byte)0xcc), unchecked((byte)0xe8), unchecked((byte)0x94), (byte)0x56, (byte)0x08, unchecked((byte)0xce), (byte)0x1a, (byte)0x3a, unchecked((byte)0xd2), unchecked((byte)0xe1), unchecked((byte)0xdf), unchecked((byte)0xb5), (byte)0x38, (byte)0x6e, (byte)0x0e, unchecked((byte)0xe5), unchecked((byte)0xf4), unchecked((byte)0xf9), unchecked((byte)0x86), unchecked((byte)0xe9), (byte)0x4f, unchecked((byte)0xd6), unchecked((byte)0x85), (byte)0x23, unchecked((byte)0xcf), (byte)0x32, unchecked((byte)0x99), (byte)0x31, (byte)0x14, unchecked((byte)0xae), unchecked((byte)0xee), unchecked((byte)0xc8), (byte)0x48, unchecked((byte)0xd3), (byte)0x30, unchecked((byte)0xa1), unchecked((byte)0x92), (byte)0x41, unchecked((byte)0xb1), (byte)0x18, unchecked((byte)0xc4), (byte)0x2c, (byte)0x71, (byte)0x72, (byte)0x44, (byte)0x15, unchecked((byte)0xfd), (byte)0x37, unchecked((byte)0xbe), (byte)0x5f, unchecked((byte)0xaa), unchecked((byte)0x9b), unchecked((byte)0x88), unchecked((byte)0xd8), unchecked((byte)0xab), unchecked((byte)0x89), unchecked((byte)0x9c), unchecked((byte)0xfa), (byte)0x60, unchecked((byte)0xea), unchecked((byte)0xbc), (byte)0x62, (byte)0x0c, (byte)0x24, unchecked((byte)0xa6), unchecked((byte)0xa8), unchecked((byte)0xec), (byte)0x67, (byte)0x20, unchecked((byte)0xdb), (byte)0x7c, (byte)0x28, unchecked((byte)0xdd), unchecked((byte)0xac), (byte)0x5b, (byte)0x34, (byte)0x7e, (byte)0x10, unchecked((byte)0xf1), (byte)0x7b, unchecked((byte)0x8f), (byte)0x63, unchecked((byte)0xa0), (byte)0x05, unchecked((byte)0x9a), (byte)0x43, (byte)0x77, (byte)0x21, unchecked((byte)0xbf), (byte)0x27, (byte)0x09, unchecked((byte)0xc3), unchecked((byte)0x9f), unchecked((byte)0xb6), unchecked((byte)0xd7), (byte)0x29, unchecked((byte)0xc2), unchecked((byte)0xeb), unchecked((byte)0xc0), unchecked((byte)0xa4), unchecked((byte)0x8b), unchecked((byte)0x8c), (byte)0x1d, unchecked((byte)0xfb), unchecked((byte)0xff), unchecked((byte)0xc1), unchecked((byte)0xb2), unchecked((byte)0x97), (byte)0x2e, unchecked((byte)0xf8), (byte)0x65, unchecked((byte)0xf6), (byte)0x75, (byte)0x07, (byte)0x04, (byte)0x49, (byte)0x33, unchecked((byte)0xe4), unchecked((byte)0xd9), unchecked((byte)0xb9), unchecked((byte)0xd0), (byte)0x42, unchecked((byte)0xc7), (byte)0x6c, unchecked((byte)0x90), (byte)0x00, unchecked((byte)0x8e), (byte)0x6f, (byte)0x50, (byte)0x01, unchecked((byte)0xc5), unchecked((byte)0xda), (byte)0x47, (byte)0x3f, unchecked((byte)0xcd), (byte)0x69, unchecked((byte)0xa2), unchecked((byte)0xe2), (byte)0x7a, unchecked((byte)0xa7), unchecked((byte)0xc6), unchecked((byte)0x93), (byte)0x0f, (byte)0x0a, (byte)0x06, unchecked((byte)0xe6), (byte)0x2b, unchecked((byte)0x96), unchecked((byte)0xa3), (byte)0x1c, unchecked((byte)0xaf), (byte)0x6a, (byte)0x12, unchecked((byte)0x84), (byte)0x39, unchecked((byte)0xe7), unchecked((byte)0xb0), unchecked((byte)0x82), unchecked((byte)0xf7), unchecked((byte)0xfe), unchecked((byte)0x9d), unchecked((byte)0x87), (byte)0x5c, unchecked((byte)0x81), (byte)0x35, unchecked((byte)0xde), unchecked((byte)0xb4), unchecked((byte)0xa5), unchecked((byte)0xfc), unchecked((byte)0x80), unchecked((byte)0xef), unchecked((byte)0xcb), unchecked((byte)0xbb), (byte)0x6b, (byte)0x76, unchecked((byte)0xba), (byte)0x5a, (byte)0x7d, (byte)0x78, (byte)0x0b, unchecked((byte)0x95), unchecked((byte)0xe3), unchecked((byte)0xad), (byte)0x74, unchecked((byte)0x98), (byte)0x3b, (byte)0x36, (byte)0x64, (byte)0x6d, unchecked((byte)0xdc), unchecked((byte)0xf0), (byte)0x59, unchecked((byte)0xa9), (byte)0x4c, (byte)0x17, (byte)0x7f, unchecked((byte)0x91), unchecked((byte)0xb8), unchecked((byte)0xc9), (byte)0x57, (byte)0x1b, unchecked((byte)0xe0), (byte)0x61};

		private static readonly byte[] T0 = new byte[]{unchecked((byte)0xa4), unchecked((byte)0xa2), unchecked((byte)0xa9), unchecked((byte)0xc5), (byte)0x4e, unchecked((byte)0xc9), (byte)0x03, unchecked((byte)0xd9), (byte)0x7e, (byte)0x0f, unchecked((byte)0xd2), unchecked((byte)0xad), unchecked((byte)0xe7), unchecked((byte)0xd3), (byte)0x27, (byte)0x5b, unchecked((byte)0xe3), unchecked((byte)0xa1), unchecked((byte)0xe8), unchecked((byte)0xe6), (byte)0x7c, (byte)0x2a, (byte)0x55, (byte)0x0c, unchecked((byte)0x86), (byte)0x39, unchecked((byte)0xd7), unchecked((byte)0x8d), unchecked((byte)0xb8), (byte)0x12, (byte)0x6f, (byte)0x28, unchecked((byte)0xcd), unchecked((byte)0x8a), (byte)0x70, (byte)0x56, (byte)0x72, unchecked((byte)0xf9), unchecked((byte)0xbf), (byte)0x4f, (byte)0x73, unchecked((byte)0xe9), unchecked((byte)0xf7), (byte)0x57, (byte)0x16, unchecked((byte)0xac), (byte)0x50, unchecked((byte)0xc0), unchecked((byte)0x9d), unchecked((byte)0xb7), (byte)0x47, (byte)0x71, (byte)0x60, unchecked((byte)0xc4), (byte)0x74, (byte)0x43, (byte)0x6c, (byte)0x1f, unchecked((byte)0x93), (byte)0x77, unchecked((byte)0xdc), unchecked((byte)0xce), (byte)0x20, unchecked((byte)0x8c), unchecked((byte)0x99), (byte)0x5f, (byte)0x44, (byte)0x01, unchecked((byte)0xf5), (byte)0x1e, unchecked((byte)0x87), (byte)0x5e, (byte)0x61, (byte)0x2c, (byte)0x4b, (byte)0x1d, unchecked((byte)0x81), (byte)0x15, unchecked((byte)0xf4), (byte)0x23, unchecked((byte)0xd6), unchecked((byte)0xea), unchecked((byte)0xe1), (byte)0x67, unchecked((byte)0xf1), (byte)0x7f, unchecked((byte)0xfe), unchecked((byte)0xda), (byte)0x3c, (byte)0x07, (byte)0x53, (byte)0x6a, unchecked((byte)0x84), unchecked((byte)0x9c), unchecked((byte)0xcb), (byte)0x02, unchecked((byte)0x83), (byte)0x33, unchecked((byte)0xdd), (byte)0x35, unchecked((byte)0xe2), (byte)0x59, (byte)0x5a, unchecked((byte)0x98), unchecked((byte)0xa5), unchecked((byte)0x92), (byte)0x64, (byte)0x04, (byte)0x06, (byte)0x10, (byte)0x4d, (byte)0x1c, unchecked((byte)0x97), (byte)0x08, (byte)0x31, unchecked((byte)0xee), unchecked((byte)0xab), (byte)0x05, unchecked((byte)0xaf), (byte)0x79, unchecked((byte)0xa0), (byte)0x18, (byte)0x46, (byte)0x6d, unchecked((byte)0xfc), unchecked((byte)0x89), unchecked((byte)0xd4), unchecked((byte)0xc7), unchecked((byte)0xff), unchecked((byte)0xf0), unchecked((byte)0xcf), (byte)0x42, unchecked((byte)0x91), unchecked((byte)0xf8), (byte)0x68, (byte)0x0a, (byte)0x65, unchecked((byte)0x8e), unchecked((byte)0xb6), unchecked((byte)0xfd), unchecked((byte)0xc3), unchecked((byte)0xef), (byte)0x78, (byte)0x4c, unchecked((byte)0xcc), unchecked((byte)0x9e), (byte)0x30, (byte)0x2e, unchecked((byte)0xbc), (byte)0x0b, (byte)0x54, (byte)0x1a, unchecked((byte)0xa6), unchecked((byte)0xbb), (byte)0x26, unchecked((byte)0x80), (byte)0x48, unchecked((byte)0x94), (byte)0x32, (byte)0x7d, unchecked((byte)0xa7), (byte)0x3f, unchecked((byte)0xae), (byte)0x22, (byte)0x3d, (byte)0x66, unchecked((byte)0xaa), unchecked((byte)0xf6), (byte)0x00, (byte)0x5d, unchecked((byte)0xbd), (byte)0x4a, unchecked((byte)0xe0), (byte)0x3b, unchecked((byte)0xb4), (byte)0x17, unchecked((byte)0x8b), unchecked((byte)0x9f), (byte)0x76, unchecked((byte)0xb0), (byte)0x24, unchecked((byte)0x9a), (byte)0x25, (byte)0x63, unchecked((byte)0xdb), unchecked((byte)0xeb), (byte)0x7a, (byte)0x3e, (byte)0x5c, unchecked((byte)0xb3), unchecked((byte)0xb1), (byte)0x29, unchecked((byte)0xf2), unchecked((byte)0xca), (byte)0x58, (byte)0x6e, unchecked((byte)0xd8), unchecked((byte)0xa8), (byte)0x2f, (byte)0x75, unchecked((byte)0xdf), (byte)0x14, unchecked((byte)0xfb), (byte)0x13, (byte)0x49, unchecked((byte)0x88), unchecked((byte)0xb2), unchecked((byte)0xec), unchecked((byte)0xe4), (byte)0x34, (byte)0x2d, unchecked((byte)0x96), unchecked((byte)0xc6), (byte)0x3a, unchecked((byte)0xed), unchecked((byte)0x95), (byte)0x0e, unchecked((byte)0xe5), unchecked((byte)0x85), (byte)0x6b, (byte)0x40, (byte)0x21, unchecked((byte)0x9b), (byte)0x09, (byte)0x19, (byte)0x2b, (byte)0x52, unchecked((byte)0xde), (byte)0x45, unchecked((byte)0xa3), unchecked((byte)0xfa), (byte)0x51, unchecked((byte)0xc2), unchecked((byte)0xb5), unchecked((byte)0xd1), unchecked((byte)0x90), unchecked((byte)0xb9), unchecked((byte)0xf3), (byte)0x37, unchecked((byte)0xc1), (byte)0x0d, unchecked((byte)0xba), (byte)0x41, (byte)0x11, (byte)0x38, (byte)0x7b, unchecked((byte)0xbe), unchecked((byte)0xd0), unchecked((byte)0xd5), (byte)0x69, (byte)0x36, unchecked((byte)0xc8), (byte)0x62, (byte)0x1b, unchecked((byte)0x82), unchecked((byte)0x8f)};

		private static readonly byte[] T1 = new byte[]{unchecked((byte)0x83), unchecked((byte)0xf2), (byte)0x2a, unchecked((byte)0xeb), unchecked((byte)0xe9), unchecked((byte)0xbf), (byte)0x7b, unchecked((byte)0x9c), (byte)0x34, unchecked((byte)0x96), unchecked((byte)0x8d), unchecked((byte)0x98), unchecked((byte)0xb9), (byte)0x69, unchecked((byte)0x8c), (byte)0x29, (byte)0x3d, unchecked((byte)0x88), (byte)0x68, (byte)0x06, (byte)0x39, (byte)0x11, (byte)0x4c, (byte)0x0e, unchecked((byte)0xa0), (byte)0x56, (byte)0x40, unchecked((byte)0x92), (byte)0x15, unchecked((byte)0xbc), unchecked((byte)0xb3), unchecked((byte)0xdc), (byte)0x6f, unchecked((byte)0xf8), (byte)0x26, unchecked((byte)0xba), unchecked((byte)0xbe), unchecked((byte)0xbd), (byte)0x31, unchecked((byte)0xfb), unchecked((byte)0xc3), unchecked((byte)0xfe), unchecked((byte)0x80), (byte)0x61, unchecked((byte)0xe1), (byte)0x7a, (byte)0x32, unchecked((byte)0xd2), (byte)0x70, (byte)0x20, unchecked((byte)0xa1), (byte)0x45, unchecked((byte)0xec), unchecked((byte)0xd9), (byte)0x1a, (byte)0x5d, unchecked((byte)0xb4), unchecked((byte)0xd8), (byte)0x09, unchecked((byte)0xa5), (byte)0x55, unchecked((byte)0x8e), (byte)0x37, (byte)0x76, unchecked((byte)0xa9), (byte)0x67, (byte)0x10, (byte)0x17, (byte)0x36, (byte)0x65, unchecked((byte)0xb1), unchecked((byte)0x95), (byte)0x62, (byte)0x59, (byte)0x74, unchecked((byte)0xa3), (byte)0x50, (byte)0x2f, (byte)0x4b, unchecked((byte)0xc8), unchecked((byte)0xd0), unchecked((byte)0x8f), unchecked((byte)0xcd), unchecked((byte)0xd4), (byte)0x3c, unchecked((byte)0x86), (byte)0x12, (byte)0x1d, (byte)0x23, unchecked((byte)0xef), unchecked((byte)0xf4), (byte)0x53, (byte)0x19, (byte)0x35, unchecked((byte)0xe6), (byte)0x7f, (byte)0x5e, unchecked((byte)0xd6), (byte)0x79, (byte)0x51, (byte)0x22, (byte)0x14, unchecked((byte)0xf7), (byte)0x1e, (byte)0x4a, (byte)0x42, unchecked((byte)0x9b), (byte)0x41, (byte)0x73, (byte)0x2d, unchecked((byte)0xc1), (byte)0x5c, unchecked((byte)0xa6), unchecked((byte)0xa2), unchecked((byte)0xe0), (byte)0x2e, unchecked((byte)0xd3), (byte)0x28, unchecked((byte)0xbb), unchecked((byte)0xc9), unchecked((byte)0xae), (byte)0x6a, unchecked((byte)0xd1), (byte)0x5a, (byte)0x30, unchecked((byte)0x90), unchecked((byte)0x84), unchecked((byte)0xf9), unchecked((byte)0xb2), (byte)0x58, unchecked((byte)0xcf), (byte)0x7e, unchecked((byte)0xc5), unchecked((byte)0xcb), unchecked((byte)0x97), unchecked((byte)0xe4), (byte)0x16, (byte)0x6c, unchecked((byte)0xfa), unchecked((byte)0xb0), (byte)0x6d, (byte)0x1f, (byte)0x52, unchecked((byte)0x99), (byte)0x0d, (byte)0x4e, (byte)0x03, unchecked((byte)0x91), unchecked((byte)0xc2), (byte)0x4d, (byte)0x64, (byte)0x77, unchecked((byte)0x9f), unchecked((byte)0xdd), unchecked((byte)0xc4), (byte)0x49, unchecked((byte)0x8a), unchecked((byte)0x9a), (byte)0x24, (byte)0x38, unchecked((byte)0xa7), (byte)0x57, unchecked((byte)0x85), unchecked((byte)0xc7), (byte)0x7c, (byte)0x7d, unchecked((byte)0xe7), unchecked((byte)0xf6), unchecked((byte)0xb7), unchecked((byte)0xac), (byte)0x27, (byte)0x46, unchecked((byte)0xde), unchecked((byte)0xdf), (byte)0x3b, unchecked((byte)0xd7), unchecked((byte)0x9e), (byte)0x2b, (byte)0x0b, unchecked((byte)0xd5), (byte)0x13, (byte)0x75, unchecked((byte)0xf0), (byte)0x72, unchecked((byte)0xb6), unchecked((byte)0x9d), (byte)0x1b, (byte)0x01, (byte)0x3f, (byte)0x44, unchecked((byte)0xe5), unchecked((byte)0x87), unchecked((byte)0xfd), (byte)0x07, unchecked((byte)0xf1), unchecked((byte)0xab), unchecked((byte)0x94), (byte)0x18, unchecked((byte)0xea), unchecked((byte)0xfc), (byte)0x3a, unchecked((byte)0x82), (byte)0x5f, (byte)0x05, (byte)0x54, unchecked((byte)0xdb), (byte)0x00, unchecked((byte)0x8b), unchecked((byte)0xe3), (byte)0x48, (byte)0x0c, unchecked((byte)0xca), (byte)0x78, unchecked((byte)0x89), (byte)0x0a, unchecked((byte)0xff), (byte)0x3e, (byte)0x5b, unchecked((byte)0x81), unchecked((byte)0xee), (byte)0x71, unchecked((byte)0xe2), unchecked((byte)0xda), (byte)0x2c, unchecked((byte)0xb8), unchecked((byte)0xb5), unchecked((byte)0xcc), (byte)0x6e, unchecked((byte)0xa8), (byte)0x6b, unchecked((byte)0xad), (byte)0x60, unchecked((byte)0xc6), (byte)0x08, (byte)0x04, (byte)0x02, unchecked((byte)0xe8), unchecked((byte)0xf5), (byte)0x4f, unchecked((byte)0xa4), unchecked((byte)0xf3), unchecked((byte)0xc0), unchecked((byte)0xce), (byte)0x43, (byte)0x25, (byte)0x1c, (byte)0x21, (byte)0x33, (byte)0x0f, unchecked((byte)0xaf), (byte)0x47, unchecked((byte)0xed), (byte)0x66, (byte)0x63, unchecked((byte)0x93), unchecked((byte)0xaa)};

		private static readonly byte[] T2 = new byte[]{(byte)0x45, unchecked((byte)0xd4), (byte)0x0b, (byte)0x43, unchecked((byte)0xf1), (byte)0x72, unchecked((byte)0xed), unchecked((byte)0xa4), unchecked((byte)0xc2), (byte)0x38, unchecked((byte)0xe6), (byte)0x71, unchecked((byte)0xfd), unchecked((byte)0xb6), (byte)0x3a, unchecked((byte)0x95), (byte)0x50, (byte)0x44, (byte)0x4b, unchecked((byte)0xe2), (byte)0x74, (byte)0x6b, (byte)0x1e, (byte)0x11, (byte)0x5a, unchecked((byte)0xc6), unchecked((byte)0xb4), unchecked((byte)0xd8), unchecked((byte)0xa5), unchecked((byte)0x8a), (byte)0x70, unchecked((byte)0xa3), unchecked((byte)0xa8), unchecked((byte)0xfa), (byte)0x05, unchecked((byte)0xd9), unchecked((byte)0x97), (byte)0x40, unchecked((byte)0xc9), unchecked((byte)0x90), unchecked((byte)0x98), unchecked((byte)0x8f), unchecked((byte)0xdc), (byte)0x12, (byte)0x31, (byte)0x2c, (byte)0x47, (byte)0x6a, unchecked((byte)0x99), unchecked((byte)0xae), unchecked((byte)0xc8), (byte)0x7f, unchecked((byte)0xf9), (byte)0x4f, (byte)0x5d, unchecked((byte)0x96), (byte)0x6f, unchecked((byte)0xf4), unchecked((byte)0xb3), (byte)0x39, (byte)0x21, unchecked((byte)0xda), unchecked((byte)0x9c), unchecked((byte)0x85), unchecked((byte)0x9e), (byte)0x3b, unchecked((byte)0xf0), unchecked((byte)0xbf), unchecked((byte)0xef), (byte)0x06, unchecked((byte)0xee), unchecked((byte)0xe5), (byte)0x5f, (byte)0x20, (byte)0x10, unchecked((byte)0xcc), (byte)0x3c, (byte)0x54, (byte)0x4a, (byte)0x52, unchecked((byte)0x94), (byte)0x0e, unchecked((byte)0xc0), (byte)0x28, unchecked((byte)0xf6), (byte)0x56, (byte)0x60, unchecked((byte)0xa2), unchecked((byte)0xe3), (byte)0x0f, unchecked((byte)0xec), unchecked((byte)0x9d), (byte)0x24, unchecked((byte)0x83), (byte)0x7e, unchecked((byte)0xd5), (byte)0x7c, unchecked((byte)0xeb), (byte)0x18, unchecked((byte)0xd7), unchecked((byte)0xcd), unchecked((byte)0xdd), (byte)0x78, unchecked((byte)0xff), unchecked((byte)0xdb), unchecked((byte)0xa1), (byte)0x09, unchecked((byte)0xd0), (byte)0x76, unchecked((byte)0x84), (byte)0x75, unchecked((byte)0xbb), (byte)0x1d, (byte)0x1a, (byte)0x2f, unchecked((byte)0xb0), unchecked((byte)0xfe), unchecked((byte)0xd6), (byte)0x34, (byte)0x63, (byte)0x35, unchecked((byte)0xd2), (byte)0x2a, (byte)0x59, (byte)0x6d, (byte)0x4d, (byte)0x77, unchecked((byte)0xe7), unchecked((byte)0x8e), (byte)0x61, unchecked((byte)0xcf), unchecked((byte)0x9f), unchecked((byte)0xce), (byte)0x27, unchecked((byte)0xf5), unchecked((byte)0x80), unchecked((byte)0x86), unchecked((byte)0xc7), unchecked((byte)0xa6), unchecked((byte)0xfb), unchecked((byte)0xf8), unchecked((byte)0x87), unchecked((byte)0xab), (byte)0x62, (byte)0x3f, unchecked((byte)0xdf), (byte)0x48, (byte)0x00, (byte)0x14, unchecked((byte)0x9a), unchecked((byte)0xbd), (byte)0x5b, (byte)0x04, unchecked((byte)0x92), (byte)0x02, (byte)0x25, (byte)0x65, (byte)0x4c, (byte)0x53, (byte)0x0c, unchecked((byte)0xf2), (byte)0x29, unchecked((byte)0xaf), (byte)0x17, (byte)0x6c, (byte)0x41, (byte)0x30, unchecked((byte)0xe9), unchecked((byte)0x93), (byte)0x55, unchecked((byte)0xf7), unchecked((byte)0xac), (byte)0x68, (byte)0x26, unchecked((byte)0xc4), (byte)0x7d, unchecked((byte)0xca), (byte)0x7a, (byte)0x3e, unchecked((byte)0xa0), (byte)0x37, (byte)0x03, unchecked((byte)0xc1), (byte)0x36, (byte)0x69, (byte)0x66, (byte)0x08, (byte)0x16, unchecked((byte)0xa7), unchecked((byte)0xbc), unchecked((byte)0xc5), unchecked((byte)0xd3), (byte)0x22, unchecked((byte)0xb7), (byte)0x13, (byte)0x46, (byte)0x32, unchecked((byte)0xe8), (byte)0x57, unchecked((byte)0x88), (byte)0x2b, unchecked((byte)0x81), unchecked((byte)0xb2), (byte)0x4e, (byte)0x64, (byte)0x1c, unchecked((byte)0xaa), unchecked((byte)0x91), (byte)0x58, (byte)0x2e, unchecked((byte)0x9b), (byte)0x5c, (byte)0x1b, (byte)0x51, (byte)0x73, (byte)0x42, (byte)0x23, (byte)0x01, (byte)0x6e, unchecked((byte)0xf3), (byte)0x0d, unchecked((byte)0xbe), (byte)0x3d, (byte)0x0a, (byte)0x2d, (byte)0x1f, (byte)0x67, (byte)0x33, (byte)0x19, (byte)0x7b, (byte)0x5e, unchecked((byte)0xea), unchecked((byte)0xde), unchecked((byte)0x8b), unchecked((byte)0xcb), unchecked((byte)0xa9), unchecked((byte)0x8c), unchecked((byte)0x8d), unchecked((byte)0xad), (byte)0x49, unchecked((byte)0x82), unchecked((byte)0xe4), unchecked((byte)0xba), unchecked((byte)0xc3), (byte)0x15, unchecked((byte)0xd1), unchecked((byte)0xe0), unchecked((byte)0x89), unchecked((byte)0xfc), unchecked((byte)0xb1), unchecked((byte)0xb9), unchecked((byte)0xb5), (byte)0x07, (byte)0x79, unchecked((byte)0xb8), unchecked((byte)0xe1)};

		private static readonly byte[] T3 = new byte[]{unchecked((byte)0xb2), unchecked((byte)0xb6), (byte)0x23, (byte)0x11, unchecked((byte)0xa7), unchecked((byte)0x88), unchecked((byte)0xc5), unchecked((byte)0xa6), (byte)0x39, unchecked((byte)0x8f), unchecked((byte)0xc4), unchecked((byte)0xe8), (byte)0x73, (byte)0x22, (byte)0x43, unchecked((byte)0xc3), unchecked((byte)0x82), (byte)0x27, unchecked((byte)0xcd), (byte)0x18, (byte)0x51, (byte)0x62, (byte)0x2d, unchecked((byte)0xf7), (byte)0x5c, (byte)0x0e, (byte)0x3b, unchecked((byte)0xfd), unchecked((byte)0xca), unchecked((byte)0x9b), (byte)0x0d, (byte)0x0f, (byte)0x79, unchecked((byte)0x8c), (byte)0x10, (byte)0x4c, (byte)0x74, (byte)0x1c, (byte)0x0a, unchecked((byte)0x8e), (byte)0x7c, unchecked((byte)0x94), (byte)0x07, unchecked((byte)0xc7), (byte)0x5e, (byte)0x14, unchecked((byte)0xa1), (byte)0x21, (byte)0x57, (byte)0x50, (byte)0x4e, unchecked((byte)0xa9), unchecked((byte)0x80), unchecked((byte)0xd9), unchecked((byte)0xef), (byte)0x64, (byte)0x41, unchecked((byte)0xcf), (byte)0x3c, unchecked((byte)0xee), (byte)0x2e, (byte)0x13, (byte)0x29, unchecked((byte)0xba), (byte)0x34, (byte)0x5a, unchecked((byte)0xae), unchecked((byte)0x8a), (byte)0x61, (byte)0x33, (byte)0x12, unchecked((byte)0xb9), (byte)0x55, unchecked((byte)0xa8), (byte)0x15, (byte)0x05, unchecked((byte)0xf6), (byte)0x03, (byte)0x06, (byte)0x49, unchecked((byte)0xb5), (byte)0x25, (byte)0x09, (byte)0x16, (byte)0x0c, (byte)0x2a, (byte)0x38, unchecked((byte)0xfc), (byte)0x20, unchecked((byte)0xf4), unchecked((byte)0xe5), (byte)0x7f, unchecked((byte)0xd7), (byte)0x31, (byte)0x2b, (byte)0x66, (byte)0x6f, unchecked((byte)0xff), (byte)0x72, unchecked((byte)0x86), unchecked((byte)0xf0), unchecked((byte)0xa3), (byte)0x2f, (byte)0x78, (byte)0x00, unchecked((byte)0xbc), unchecked((byte)0xcc), unchecked((byte)0xe2), unchecked((byte)0xb0), unchecked((byte)0xf1), (byte)0x42, unchecked((byte)0xb4), (byte)0x30, (byte)0x5f, (byte)0x60, (byte)0x04, unchecked((byte)0xec), unchecked((byte)0xa5), unchecked((byte)0xe3), unchecked((byte)0x8b), unchecked((byte)0xe7), (byte)0x1d, unchecked((byte)0xbf), unchecked((byte)0x84), (byte)0x7b, unchecked((byte)0xe6), unchecked((byte)0x81), unchecked((byte)0xf8), unchecked((byte)0xde), unchecked((byte)0xd8), unchecked((byte)0xd2), (byte)0x17, unchecked((byte)0xce), (byte)0x4b, (byte)0x47, unchecked((byte)0xd6), (byte)0x69, (byte)0x6c, (byte)0x19, unchecked((byte)0x99), unchecked((byte)0x9a), (byte)0x01, unchecked((byte)0xb3), unchecked((byte)0x85), unchecked((byte)0xb1), unchecked((byte)0xf9), (byte)0x59, unchecked((byte)0xc2), (byte)0x37, unchecked((byte)0xe9), unchecked((byte)0xc8), unchecked((byte)0xa0), unchecked((byte)0xed), (byte)0x4f, unchecked((byte)0x89), (byte)0x68, (byte)0x6d, unchecked((byte)0xd5), (byte)0x26, unchecked((byte)0x91), unchecked((byte)0x87), (byte)0x58, unchecked((byte)0xbd), unchecked((byte)0xc9), unchecked((byte)0x98), unchecked((byte)0xdc), (byte)0x75, unchecked((byte)0xc0), (byte)0x76, unchecked((byte)0xf5), (byte)0x67, (byte)0x6b, (byte)0x7e, unchecked((byte)0xeb), (byte)0x52, unchecked((byte)0xcb), unchecked((byte)0xd1), (byte)0x5b, unchecked((byte)0x9f), (byte)0x0b, unchecked((byte)0xdb), (byte)0x40, unchecked((byte)0x92), (byte)0x1a, unchecked((byte)0xfa), unchecked((byte)0xac), unchecked((byte)0xe4), unchecked((byte)0xe1), (byte)0x71, (byte)0x1f, (byte)0x65, unchecked((byte)0x8d), unchecked((byte)0x97), unchecked((byte)0x9e), unchecked((byte)0x95), unchecked((byte)0x90), (byte)0x5d, unchecked((byte)0xb7), unchecked((byte)0xc1), unchecked((byte)0xaf), (byte)0x54, unchecked((byte)0xfb), (byte)0x02, unchecked((byte)0xe0), (byte)0x35, unchecked((byte)0xbb), (byte)0x3a, (byte)0x4d, unchecked((byte)0xad), (byte)0x2c, (byte)0x3d, (byte)0x56, (byte)0x08, (byte)0x1b, (byte)0x4a, unchecked((byte)0x93), (byte)0x6a, unchecked((byte)0xab), unchecked((byte)0xb8), (byte)0x7a, unchecked((byte)0xf2), (byte)0x7d, unchecked((byte)0xda), (byte)0x3f, unchecked((byte)0xfe), (byte)0x3e, unchecked((byte)0xbe), unchecked((byte)0xea), unchecked((byte)0xaa), (byte)0x44, unchecked((byte)0xc6), unchecked((byte)0xd0), (byte)0x36, (byte)0x48, (byte)0x70, unchecked((byte)0x96), (byte)0x77, (byte)0x24, (byte)0x53, unchecked((byte)0xdf), unchecked((byte)0xf3), unchecked((byte)0x83), (byte)0x28, (byte)0x32, (byte)0x45, (byte)0x1e, unchecked((byte)0xa4), unchecked((byte)0xd3), unchecked((byte)0xa2), (byte)0x46, (byte)0x6e, unchecked((byte)0x9c), unchecked((byte)0xdd), (byte)0x63, unchecked((byte)0xd4), unchecked((byte)0x9d)};
	}

}