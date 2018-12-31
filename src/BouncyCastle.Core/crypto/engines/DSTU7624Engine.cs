using org.bouncycastle.Port;
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
					Pack.ulongToLittleEndian(internalState, @out, outOff);
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
					Pack.ulongToLittleEndian(internalState, @out, outOff);
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

				int lo0 = (int)c0, hi0 = (int)((long)(c0 >> 32));
				int lo1 = (int)c1, hi1 = (int)((long)(c1 >> 32));

				{
					byte t0 = T0[lo0 & 0xFF];
					byte t1 = T1[((int)((uint)lo0 >> 8)) & 0xFF];
					byte t2 = T2[((int)((uint)lo0 >> 16)) & 0xFF];
					byte t3 = T3[(int)((uint)lo0 >> 24)];
					lo0 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
					byte t4 = T0[hi1 & 0xFF];
					byte t5 = T1[((int)((uint)hi1 >> 8)) & 0xFF];
					byte t6 = T2[((int)((uint)hi1 >> 16)) & 0xFF];
					byte t7 = T3[(int)((uint)hi1 >> 24)];
					hi1 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
				    c0 = (ulong)lo0 | ((ulong)hi1 << 32);
                }

				{
					byte t0 = T0[lo1 & 0xFF];
					byte t1 = T1[((int)((uint)lo1 >> 8)) & 0xFF];
					byte t2 = T2[((int)((uint)lo1 >> 16)) & 0xFF];
					byte t3 = T3[(int)((uint)lo1 >> 24)];
					lo1 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
					byte t4 = T0[hi0 & 0xFF];
					byte t5 = T1[((int)((uint)hi0 >> 8)) & 0xFF];
					byte t6 = T2[((int)((uint)hi0 >> 16)) & 0xFF];
					byte t7 = T3[(int)((uint)hi0 >> 24)];
					hi0 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
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

			Pack.ulongToLittleEndian(c0, @out, outOff);
			Pack.ulongToLittleEndian(c1, @out, outOff + 8);
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
				int lo0 = (int)c0, hi0 = (int)((long)(c0 >> 32));
				int lo1 = (int)c1, hi1 = (int)((long)(c1 >> 32));

				{
					byte t0 = S0[lo0 & 0xFF];
					byte t1 = S1[((int)((uint)lo0 >> 8)) & 0xFF];
					byte t2 = S2[((int)((uint)lo0 >> 16)) & 0xFF];
					byte t3 = S3[(int)((uint)lo0 >> 24)];
					lo0 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
					byte t4 = S0[hi1 & 0xFF];
					byte t5 = S1[((int)((uint)hi1 >> 8)) & 0xFF];
					byte t6 = S2[((int)((uint)hi1 >> 16)) & 0xFF];
					byte t7 = S3[(int)((uint)hi1 >> 24)];
					hi1 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
				    c0 = (ulong)lo0 | ((ulong)hi1 << 32);
                }

				{
					byte t0 = S0[lo1 & 0xFF];
					byte t1 = S1[((int)((uint)lo1 >> 8)) & 0xFF];
					byte t2 = S2[((int)((uint)lo1 >> 16)) & 0xFF];
					byte t3 = S3[(int)((uint)lo1 >> 24)];
					lo1 = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
					byte t4 = S0[hi0 & 0xFF];
					byte t5 = S1[((int)((uint)hi0 >> 8)) & 0xFF];
					byte t6 = S2[((int)((uint)hi0 >> 16)) & 0xFF];
					byte t7 = S3[(int)((uint)hi0 >> 24)];
					hi0 = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
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

			Pack.ulongToLittleEndian(c0, @out, outOff);
			Pack.ulongToLittleEndian(c1, @out, outOff + 8);
		}

		private void subBytes()
		{
			for (int i = 0; i < wordsInBlock; i++)
			{
				ulong u = internalState[i];
				int lo = (int)u, hi = (int)((long)(u >> 32));
				byte t0 = S0[lo & 0xFF];
				byte t1 = S1[((int)((uint)lo >> 8)) & 0xFF];
				byte t2 = S2[((int)((uint)lo >> 16)) & 0xFF];
				byte t3 = S3[(int)((uint)lo >> 24)];
				lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
				byte t4 = S0[hi & 0xFF];
				byte t5 = S1[((int)((uint)hi >> 8)) & 0xFF];
				byte t6 = S2[((int)((uint)hi >> 16)) & 0xFF];
				byte t7 = S3[(int)((uint)hi >> 24)];
				hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
			    internalState[i] = (ulong)lo | ((ulong)hi << 32);
            }
		}

		private void invSubBytes()
		{
			for (int i = 0; i < wordsInBlock; i++)
			{
				ulong u = internalState[i];
				int lo = (int)u, hi = (int)((long)(u >> 32));
				byte t0 = T0[lo & 0xFF];
				byte t1 = T1[((int)((uint)lo >> 8)) & 0xFF];
				byte t2 = T2[((int)((uint)lo >> 16)) & 0xFF];
				byte t3 = T3[(int)((uint)lo >> 24)];
				lo = (t0 & 0xFF) | ((t1 & 0xFF) << 8) | ((t2 & 0xFF) << 16) | (t3 << 24);
				byte t4 = T0[hi & 0xFF];
				byte t5 = T1[((int)((uint)hi >> 8)) & 0xFF];
				byte t6 = T2[((int)((uint)hi >> 16)) & 0xFF];
				byte t7 = T3[(int)((uint)hi >> 24)];
				hi = (t4 & 0xFF) | ((t5 & 0xFF) << 8) | ((t6 & 0xFF) << 16) | (t7 << 24);
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

				d = (c0 ^ c1) & unchecked(0xFFFFFFFF00000000UL);
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

				d = (c0 ^ c2) & unchecked(0xFFFFFFFF00000000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x0000FFFFFFFF0000UL;
				c1 ^= d;
				c3 ^= d;

				d = (c0 ^ c1) & unchecked(0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked(0xFFFF0000FFFF0000UL);
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

				d = (c0 ^ c4) & unchecked(0xFFFFFFFF00000000UL);
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

				d = (c0 ^ c2) & unchecked(0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x00FFFF0000FFFF00UL;
				c1 ^= d;
				c3 ^= d;
				d = (c4 ^ c6) & unchecked(0xFFFF0000FFFF0000UL);
				c4 ^= d;
				c6 ^= d;
				d = (c5 ^ c7) & 0x00FFFF0000FFFF00UL;
				c5 ^= d;
				c7 ^= d;

				d = (c0 ^ c1) & unchecked(0xFF00FF00FF00FF00UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked(0xFF00FF00FF00FF00UL);
				c2 ^= d;
				c3 ^= d;
				d = (c4 ^ c5) & unchecked(0xFF00FF00FF00FF00UL);
				c4 ^= d;
				c5 ^= d;
				d = (c6 ^ c7) & unchecked(0xFF00FF00FF00FF00UL);
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

				d = (c0 ^ c1) & unchecked(0xFFFFFFFF00000000UL);
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

				d = (c0 ^ c1) & unchecked(0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked(0xFFFF0000FFFF0000UL);
				c2 ^= d;
				c3 ^= d;

				d = (c0 ^ c2) & unchecked(0xFFFFFFFF00000000UL);
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

				d = (c0 ^ c1) & unchecked(0xFF00FF00FF00FF00UL);
				c0 ^= d;
				c1 ^= d;
				d = (c2 ^ c3) & unchecked(0xFF00FF00FF00FF00UL);
				c2 ^= d;
				c3 ^= d;
				d = (c4 ^ c5) & unchecked(0xFF00FF00FF00FF00UL);
				c4 ^= d;
				c5 ^= d;
				d = (c6 ^ c7) & unchecked(0xFF00FF00FF00FF00UL);
				c6 ^= d;
				c7 ^= d;

				d = (c0 ^ c2) & unchecked(0xFFFF0000FFFF0000UL);
				c0 ^= d;
				c2 ^= d;
				d = (c1 ^ c3) & 0x00FFFF0000FFFF00UL;
				c1 ^= d;
				c3 ^= d;
				d = (c4 ^ c6) & unchecked(0xFFFF0000FFFF0000UL);
				c4 ^= d;
				c6 ^= d;
				d = (c5 ^ c7) & 0x00FFFF0000FFFF00UL;
				c5 ^= d;
				c7 ^= d;

				d = (c0 ^ c4) & unchecked(0xFFFFFFFF00000000UL);
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
			return x >> n | (x << -n);
		}

		private void rotateLeft(ulong[] x, ulong[] z)
		{
			switch (wordsInBlock)
			{
			case 2:
			{
				ulong x0 = x[0], x1 = x[1];
				z[0] = x0 >> 56 | (x1 << 8);
				z[1] = x1 >> 56 | (x0 << 8);
				break;
			}
			case 4:
			{
				ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
				z[0] = x1 >> 24 | (x2 << 40);
				z[1] = x2 >> 24 | (x3 << 40);
				z[2] = x3 >> 24 | (x0 << 40);
				z[3] = x0 >> 24 | (x1 << 40);
				break;
			}
			case 8:
			{
				ulong x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3];
				ulong x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
				z[0] = x2 >> 24 | (x3 << 40);
				z[1] = x3 >> 24 | (x4 << 40);
				z[2] = x4 >> 24 | (x5 << 40);
				z[3] = x5 >> 24 | (x6 << 40);
				z[4] = x6 >> 24 | (x7 << 40);
				z[5] = x7 >> 24 | (x0 << 40);
				z[6] = x0 >> 24 | (x1 << 40);
				z[7] = x1 >> 24 | (x2 << 40);
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

		private static readonly byte[] S0 = new byte[]{unchecked(0xa8), 0x43, 0x5f, 0x06, 0x6b, 0x75, 0x6c, 0x59, 0x71, unchecked(0xdf), unchecked(0x87), unchecked(0x95), 0x17, unchecked(0xf0), unchecked(0xd8), 0x09, 0x6d, unchecked(0xf3), 0x1d, unchecked(0xcb), unchecked(0xc9), 0x4d, 0x2c, unchecked(0xaf), 0x79, unchecked(0xe0), unchecked(0x97), unchecked(0xfd), 0x6f, 0x4b, 0x45, 0x39, 0x3e, unchecked(0xdd), unchecked(0xa3), 0x4f, unchecked(0xb4), unchecked(0xb6), unchecked(0x9a), 0x0e, 0x1f, unchecked(0xbf), 0x15, unchecked(0xe1), 0x49, unchecked(0xd2), unchecked(0x93), unchecked(0xc6), unchecked(0x92), 0x72, unchecked(0x9e), 0x61, unchecked(0xd1), 0x63, unchecked(0xfa), unchecked(0xee), unchecked(0xf4), 0x19, unchecked(0xd5), unchecked(0xad), 0x58, unchecked(0xa4), unchecked(0xbb), unchecked(0xa1), unchecked(0xdc), unchecked(0xf2), unchecked(0x83), 0x37, 0x42, unchecked(0xe4), 0x7a, 0x32, unchecked(0x9c), unchecked(0xcc), unchecked(0xab), 0x4a, unchecked(0x8f), 0x6e, 0x04, 0x27, 0x2e, unchecked(0xe7), unchecked(0xe2), 0x5a, unchecked(0x96), 0x16, 0x23, 0x2b, unchecked(0xc2), 0x65, 0x66, 0x0f, unchecked(0xbc), unchecked(0xa9), 0x47, 0x41, 0x34, 0x48, unchecked(0xfc), unchecked(0xb7), 0x6a, unchecked(0x88), unchecked(0xa5), 0x53, unchecked(0x86), unchecked(0xf9), 0x5b, unchecked(0xdb), 0x38, 0x7b, unchecked(0xc3), 0x1e, 0x22, 0x33, 0x24, 0x28, 0x36, unchecked(0xc7), unchecked(0xb2), 0x3b, unchecked(0x8e), 0x77, unchecked(0xba), unchecked(0xf5), 0x14, unchecked(0x9f), 0x08, 0x55, unchecked(0x9b), 0x4c, unchecked(0xfe), 0x60, 0x5c, unchecked(0xda), 0x18, 0x46, unchecked(0xcd), 0x7d, 0x21, unchecked(0xb0), 0x3f, 0x1b, unchecked(0x89), unchecked(0xff), unchecked(0xeb), unchecked(0x84), 0x69, 0x3a, unchecked(0x9d), unchecked(0xd7), unchecked(0xd3), 0x70, 0x67, 0x40, unchecked(0xb5), unchecked(0xde), 0x5d, 0x30, unchecked(0x91), unchecked(0xb1), 0x78, 0x11, 0x01, unchecked(0xe5), 0x00, 0x68, unchecked(0x98), unchecked(0xa0), unchecked(0xc5), 0x02, unchecked(0xa6), 0x74, 0x2d, 0x0b, unchecked(0xa2), 0x76, unchecked(0xb3), unchecked(0xbe), unchecked(0xce), unchecked(0xbd), unchecked(0xae), unchecked(0xe9), unchecked(0x8a), 0x31, 0x1c, unchecked(0xec), unchecked(0xf1), unchecked(0x99), unchecked(0x94), unchecked(0xaa), unchecked(0xf6), 0x26, 0x2f, unchecked(0xef), unchecked(0xe8), unchecked(0x8c), 0x35, 0x03, unchecked(0xd4), 0x7f, unchecked(0xfb), 0x05, unchecked(0xc1), 0x5e, unchecked(0x90), 0x20, 0x3d, unchecked(0x82), unchecked(0xf7), unchecked(0xea), 0x0a, 0x0d, 0x7e, unchecked(0xf8), 0x50, 0x1a, unchecked(0xc4), 0x07, 0x57, unchecked(0xb8), 0x3c, 0x62, unchecked(0xe3), unchecked(0xc8), unchecked(0xac), 0x52, 0x64, 0x10, unchecked(0xd0), unchecked(0xd9), 0x13, 0x0c, 0x12, 0x29, 0x51, unchecked(0xb9), unchecked(0xcf), unchecked(0xd6), 0x73, unchecked(0x8d), unchecked(0x81), 0x54, unchecked(0xc0), unchecked(0xed), 0x4e, 0x44, unchecked(0xa7), 0x2a, unchecked(0x85), 0x25, unchecked(0xe6), unchecked(0xca), 0x7c, unchecked(0x8b), 0x56, unchecked(0x80)};

		private static readonly byte[] S1 = new byte[]{unchecked(0xce), unchecked(0xbb), unchecked(0xeb), unchecked(0x92), unchecked(0xea), unchecked(0xcb), 0x13, unchecked(0xc1), unchecked(0xe9), 0x3a, unchecked(0xd6), unchecked(0xb2), unchecked(0xd2), unchecked(0x90), 0x17, unchecked(0xf8), 0x42, 0x15, 0x56, unchecked(0xb4), 0x65, 0x1c, unchecked(0x88), 0x43, unchecked(0xc5), 0x5c, 0x36, unchecked(0xba), unchecked(0xf5), 0x57, 0x67, unchecked(0x8d), 0x31, unchecked(0xf6), 0x64, 0x58, unchecked(0x9e), unchecked(0xf4), 0x22, unchecked(0xaa), 0x75, 0x0f, 0x02, unchecked(0xb1), unchecked(0xdf), 0x6d, 0x73, 0x4d, 0x7c, 0x26, 0x2e, unchecked(0xf7), 0x08, 0x5d, 0x44, 0x3e, unchecked(0x9f), 0x14, unchecked(0xc8), unchecked(0xae), 0x54, 0x10, unchecked(0xd8), unchecked(0xbc), 0x1a, 0x6b, 0x69, unchecked(0xf3), unchecked(0xbd), 0x33, unchecked(0xab), unchecked(0xfa), unchecked(0xd1), unchecked(0x9b), 0x68, 0x4e, 0x16, unchecked(0x95), unchecked(0x91), unchecked(0xee), 0x4c, 0x63, unchecked(0x8e), 0x5b, unchecked(0xcc), 0x3c, 0x19, unchecked(0xa1), unchecked(0x81), 0x49, 0x7b, unchecked(0xd9), 0x6f, 0x37, 0x60, unchecked(0xca), unchecked(0xe7), 0x2b, 0x48, unchecked(0xfd), unchecked(0x96), 0x45, unchecked(0xfc), 0x41, 0x12, 0x0d, 0x79, unchecked(0xe5), unchecked(0x89), unchecked(0x8c), unchecked(0xe3), 0x20, 0x30, unchecked(0xdc), unchecked(0xb7), 0x6c, 0x4a, unchecked(0xb5), 0x3f, unchecked(0x97), unchecked(0xd4), 0x62, 0x2d, 0x06, unchecked(0xa4), unchecked(0xa5), unchecked(0x83), 0x5f, 0x2a, unchecked(0xda), unchecked(0xc9), 0x00, 0x7e, unchecked(0xa2), 0x55, unchecked(0xbf), 0x11, unchecked(0xd5), unchecked(0x9c), unchecked(0xcf), 0x0e, 0x0a, 0x3d, 0x51, 0x7d, unchecked(0x93), 0x1b, unchecked(0xfe), unchecked(0xc4), 0x47, 0x09, unchecked(0x86), 0x0b, unchecked(0x8f), unchecked(0x9d), 0x6a, 0x07, unchecked(0xb9), unchecked(0xb0), unchecked(0x98), 0x18, 0x32, 0x71, 0x4b, unchecked(0xef), 0x3b, 0x70, unchecked(0xa0), unchecked(0xe4), 0x40, unchecked(0xff), unchecked(0xc3), unchecked(0xa9), unchecked(0xe6), 0x78, unchecked(0xf9), unchecked(0x8b), 0x46, unchecked(0x80), 0x1e, 0x38, unchecked(0xe1), unchecked(0xb8), unchecked(0xa8), unchecked(0xe0), 0x0c, 0x23, 0x76, 0x1d, 0x25, 0x24, 0x05, unchecked(0xf1), 0x6e, unchecked(0x94), 0x28, unchecked(0x9a), unchecked(0x84), unchecked(0xe8), unchecked(0xa3), 0x4f, 0x77, unchecked(0xd3), unchecked(0x85), unchecked(0xe2), 0x52, unchecked(0xf2), unchecked(0x82), 0x50, 0x7a, 0x2f, 0x74, 0x53, unchecked(0xb3), 0x61, unchecked(0xaf), 0x39, 0x35, unchecked(0xde), unchecked(0xcd), 0x1f, unchecked(0x99), unchecked(0xac), unchecked(0xad), 0x72, 0x2c, unchecked(0xdd), unchecked(0xd0), unchecked(0x87), unchecked(0xbe), 0x5e, unchecked(0xa6), unchecked(0xec), 0x04, unchecked(0xc6), 0x03, 0x34, unchecked(0xfb), unchecked(0xdb), 0x59, unchecked(0xb6), unchecked(0xc2), 0x01, unchecked(0xf0), 0x5a, unchecked(0xed), unchecked(0xa7), 0x66, 0x21, 0x7f, unchecked(0x8a), 0x27, unchecked(0xc7), unchecked(0xc0), 0x29, unchecked(0xd7)};

		private static readonly byte[] S2 = new byte[]{unchecked(0x93), unchecked(0xd9), unchecked(0x9a), unchecked(0xb5), unchecked(0x98), 0x22, 0x45, unchecked(0xfc), unchecked(0xba), 0x6a, unchecked(0xdf), 0x02, unchecked(0x9f), unchecked(0xdc), 0x51, 0x59, 0x4a, 0x17, 0x2b, unchecked(0xc2), unchecked(0x94), unchecked(0xf4), unchecked(0xbb), unchecked(0xa3), 0x62, unchecked(0xe4), 0x71, unchecked(0xd4), unchecked(0xcd), 0x70, 0x16, unchecked(0xe1), 0x49, 0x3c, unchecked(0xc0), unchecked(0xd8), 0x5c, unchecked(0x9b), unchecked(0xad), unchecked(0x85), 0x53, unchecked(0xa1), 0x7a, unchecked(0xc8), 0x2d, unchecked(0xe0), unchecked(0xd1), 0x72, unchecked(0xa6), 0x2c, unchecked(0xc4), unchecked(0xe3), 0x76, 0x78, unchecked(0xb7), unchecked(0xb4), 0x09, 0x3b, 0x0e, 0x41, 0x4c, unchecked(0xde), unchecked(0xb2), unchecked(0x90), 0x25, unchecked(0xa5), unchecked(0xd7), 0x03, 0x11, 0x00, unchecked(0xc3), 0x2e, unchecked(0x92), unchecked(0xef), 0x4e, 0x12, unchecked(0x9d), 0x7d, unchecked(0xcb), 0x35, 0x10, unchecked(0xd5), 0x4f, unchecked(0x9e), 0x4d, unchecked(0xa9), 0x55, unchecked(0xc6), unchecked(0xd0), 0x7b, 0x18, unchecked(0x97), unchecked(0xd3), 0x36, unchecked(0xe6), 0x48, 0x56, unchecked(0x81), unchecked(0x8f), 0x77, unchecked(0xcc), unchecked(0x9c), unchecked(0xb9), unchecked(0xe2), unchecked(0xac), unchecked(0xb8), 0x2f, 0x15, unchecked(0xa4), 0x7c, unchecked(0xda), 0x38, 0x1e, 0x0b, 0x05, unchecked(0xd6), 0x14, 0x6e, 0x6c, 0x7e, 0x66, unchecked(0xfd), unchecked(0xb1), unchecked(0xe5), 0x60, unchecked(0xaf), 0x5e, 0x33, unchecked(0x87), unchecked(0xc9), unchecked(0xf0), 0x5d, 0x6d, 0x3f, unchecked(0x88), unchecked(0x8d), unchecked(0xc7), unchecked(0xf7), 0x1d, unchecked(0xe9), unchecked(0xec), unchecked(0xed), unchecked(0x80), 0x29, 0x27, unchecked(0xcf), unchecked(0x99), unchecked(0xa8), 0x50, 0x0f, 0x37, 0x24, 0x28, 0x30, unchecked(0x95), unchecked(0xd2), 0x3e, 0x5b, 0x40, unchecked(0x83), unchecked(0xb3), 0x69, 0x57, 0x1f, 0x07, 0x1c, unchecked(0x8a), unchecked(0xbc), 0x20, unchecked(0xeb), unchecked(0xce), unchecked(0x8e), unchecked(0xab), unchecked(0xee), 0x31, unchecked(0xa2), 0x73, unchecked(0xf9), unchecked(0xca), 0x3a, 0x1a, unchecked(0xfb), 0x0d, unchecked(0xc1), unchecked(0xfe), unchecked(0xfa), unchecked(0xf2), 0x6f, unchecked(0xbd), unchecked(0x96), unchecked(0xdd), 0x43, 0x52, unchecked(0xb6), 0x08, unchecked(0xf3), unchecked(0xae), unchecked(0xbe), 0x19, unchecked(0x89), 0x32, 0x26, unchecked(0xb0), unchecked(0xea), 0x4b, 0x64, unchecked(0x84), unchecked(0x82), 0x6b, unchecked(0xf5), 0x79, unchecked(0xbf), 0x01, 0x5f, 0x75, 0x63, 0x1b, 0x23, 0x3d, 0x68, 0x2a, 0x65, unchecked(0xe8), unchecked(0x91), unchecked(0xf6), unchecked(0xff), 0x13, 0x58, unchecked(0xf1), 0x47, 0x0a, 0x7f, unchecked(0xc5), unchecked(0xa7), unchecked(0xe7), 0x61, 0x5a, 0x06, 0x46, 0x44, 0x42, 0x04, unchecked(0xa0), unchecked(0xdb), 0x39, unchecked(0x86), 0x54, unchecked(0xaa), unchecked(0x8c), 0x34, 0x21, unchecked(0x8b), unchecked(0xf8), 0x0c, 0x74, 0x67};

		private static readonly byte[] S3 = new byte[]{0x68, unchecked(0x8d), unchecked(0xca), 0x4d, 0x73, 0x4b, 0x4e, 0x2a, unchecked(0xd4), 0x52, 0x26, unchecked(0xb3), 0x54, 0x1e, 0x19, 0x1f, 0x22, 0x03, 0x46, 0x3d, 0x2d, 0x4a, 0x53, unchecked(0x83), 0x13, unchecked(0x8a), unchecked(0xb7), unchecked(0xd5), 0x25, 0x79, unchecked(0xf5), unchecked(0xbd), 0x58, 0x2f, 0x0d, 0x02, unchecked(0xed), 0x51, unchecked(0x9e), 0x11, unchecked(0xf2), 0x3e, 0x55, 0x5e, unchecked(0xd1), 0x16, 0x3c, 0x66, 0x70, 0x5d, unchecked(0xf3), 0x45, 0x40, unchecked(0xcc), unchecked(0xe8), unchecked(0x94), 0x56, 0x08, unchecked(0xce), 0x1a, 0x3a, unchecked(0xd2), unchecked(0xe1), unchecked(0xdf), unchecked(0xb5), 0x38, 0x6e, 0x0e, unchecked(0xe5), unchecked(0xf4), unchecked(0xf9), unchecked(0x86), unchecked(0xe9), 0x4f, unchecked(0xd6), unchecked(0x85), 0x23, unchecked(0xcf), 0x32, unchecked(0x99), 0x31, 0x14, unchecked(0xae), unchecked(0xee), unchecked(0xc8), 0x48, unchecked(0xd3), 0x30, unchecked(0xa1), unchecked(0x92), 0x41, unchecked(0xb1), 0x18, unchecked(0xc4), 0x2c, 0x71, 0x72, 0x44, 0x15, unchecked(0xfd), 0x37, unchecked(0xbe), 0x5f, unchecked(0xaa), unchecked(0x9b), unchecked(0x88), unchecked(0xd8), unchecked(0xab), unchecked(0x89), unchecked(0x9c), unchecked(0xfa), 0x60, unchecked(0xea), unchecked(0xbc), 0x62, 0x0c, 0x24, unchecked(0xa6), unchecked(0xa8), unchecked(0xec), 0x67, 0x20, unchecked(0xdb), 0x7c, 0x28, unchecked(0xdd), unchecked(0xac), 0x5b, 0x34, 0x7e, 0x10, unchecked(0xf1), 0x7b, unchecked(0x8f), 0x63, unchecked(0xa0), 0x05, unchecked(0x9a), 0x43, 0x77, 0x21, unchecked(0xbf), 0x27, 0x09, unchecked(0xc3), unchecked(0x9f), unchecked(0xb6), unchecked(0xd7), 0x29, unchecked(0xc2), unchecked(0xeb), unchecked(0xc0), unchecked(0xa4), unchecked(0x8b), unchecked(0x8c), 0x1d, unchecked(0xfb), unchecked(0xff), unchecked(0xc1), unchecked(0xb2), unchecked(0x97), 0x2e, unchecked(0xf8), 0x65, unchecked(0xf6), 0x75, 0x07, 0x04, 0x49, 0x33, unchecked(0xe4), unchecked(0xd9), unchecked(0xb9), unchecked(0xd0), 0x42, unchecked(0xc7), 0x6c, unchecked(0x90), 0x00, unchecked(0x8e), 0x6f, 0x50, 0x01, unchecked(0xc5), unchecked(0xda), 0x47, 0x3f, unchecked(0xcd), 0x69, unchecked(0xa2), unchecked(0xe2), 0x7a, unchecked(0xa7), unchecked(0xc6), unchecked(0x93), 0x0f, 0x0a, 0x06, unchecked(0xe6), 0x2b, unchecked(0x96), unchecked(0xa3), 0x1c, unchecked(0xaf), 0x6a, 0x12, unchecked(0x84), 0x39, unchecked(0xe7), unchecked(0xb0), unchecked(0x82), unchecked(0xf7), unchecked(0xfe), unchecked(0x9d), unchecked(0x87), 0x5c, unchecked(0x81), 0x35, unchecked(0xde), unchecked(0xb4), unchecked(0xa5), unchecked(0xfc), unchecked(0x80), unchecked(0xef), unchecked(0xcb), unchecked(0xbb), 0x6b, 0x76, unchecked(0xba), 0x5a, 0x7d, 0x78, 0x0b, unchecked(0x95), unchecked(0xe3), unchecked(0xad), 0x74, unchecked(0x98), 0x3b, 0x36, 0x64, 0x6d, unchecked(0xdc), unchecked(0xf0), 0x59, unchecked(0xa9), 0x4c, 0x17, 0x7f, unchecked(0x91), unchecked(0xb8), unchecked(0xc9), 0x57, 0x1b, unchecked(0xe0), 0x61};

		private static readonly byte[] T0 = new byte[]{unchecked(0xa4), unchecked(0xa2), unchecked(0xa9), unchecked(0xc5), 0x4e, unchecked(0xc9), 0x03, unchecked(0xd9), 0x7e, 0x0f, unchecked(0xd2), unchecked(0xad), unchecked(0xe7), unchecked(0xd3), 0x27, 0x5b, unchecked(0xe3), unchecked(0xa1), unchecked(0xe8), unchecked(0xe6), 0x7c, 0x2a, 0x55, 0x0c, unchecked(0x86), 0x39, unchecked(0xd7), unchecked(0x8d), unchecked(0xb8), 0x12, 0x6f, 0x28, unchecked(0xcd), unchecked(0x8a), 0x70, 0x56, 0x72, unchecked(0xf9), unchecked(0xbf), 0x4f, 0x73, unchecked(0xe9), unchecked(0xf7), 0x57, 0x16, unchecked(0xac), 0x50, unchecked(0xc0), unchecked(0x9d), unchecked(0xb7), 0x47, 0x71, 0x60, unchecked(0xc4), 0x74, 0x43, 0x6c, 0x1f, unchecked(0x93), 0x77, unchecked(0xdc), unchecked(0xce), 0x20, unchecked(0x8c), unchecked(0x99), 0x5f, 0x44, 0x01, unchecked(0xf5), 0x1e, unchecked(0x87), 0x5e, 0x61, 0x2c, 0x4b, 0x1d, unchecked(0x81), 0x15, unchecked(0xf4), 0x23, unchecked(0xd6), unchecked(0xea), unchecked(0xe1), 0x67, unchecked(0xf1), 0x7f, unchecked(0xfe), unchecked(0xda), 0x3c, 0x07, 0x53, 0x6a, unchecked(0x84), unchecked(0x9c), unchecked(0xcb), 0x02, unchecked(0x83), 0x33, unchecked(0xdd), 0x35, unchecked(0xe2), 0x59, 0x5a, unchecked(0x98), unchecked(0xa5), unchecked(0x92), 0x64, 0x04, 0x06, 0x10, 0x4d, 0x1c, unchecked(0x97), 0x08, 0x31, unchecked(0xee), unchecked(0xab), 0x05, unchecked(0xaf), 0x79, unchecked(0xa0), 0x18, 0x46, 0x6d, unchecked(0xfc), unchecked(0x89), unchecked(0xd4), unchecked(0xc7), unchecked(0xff), unchecked(0xf0), unchecked(0xcf), 0x42, unchecked(0x91), unchecked(0xf8), 0x68, 0x0a, 0x65, unchecked(0x8e), unchecked(0xb6), unchecked(0xfd), unchecked(0xc3), unchecked(0xef), 0x78, 0x4c, unchecked(0xcc), unchecked(0x9e), 0x30, 0x2e, unchecked(0xbc), 0x0b, 0x54, 0x1a, unchecked(0xa6), unchecked(0xbb), 0x26, unchecked(0x80), 0x48, unchecked(0x94), 0x32, 0x7d, unchecked(0xa7), 0x3f, unchecked(0xae), 0x22, 0x3d, 0x66, unchecked(0xaa), unchecked(0xf6), 0x00, 0x5d, unchecked(0xbd), 0x4a, unchecked(0xe0), 0x3b, unchecked(0xb4), 0x17, unchecked(0x8b), unchecked(0x9f), 0x76, unchecked(0xb0), 0x24, unchecked(0x9a), 0x25, 0x63, unchecked(0xdb), unchecked(0xeb), 0x7a, 0x3e, 0x5c, unchecked(0xb3), unchecked(0xb1), 0x29, unchecked(0xf2), unchecked(0xca), 0x58, 0x6e, unchecked(0xd8), unchecked(0xa8), 0x2f, 0x75, unchecked(0xdf), 0x14, unchecked(0xfb), 0x13, 0x49, unchecked(0x88), unchecked(0xb2), unchecked(0xec), unchecked(0xe4), 0x34, 0x2d, unchecked(0x96), unchecked(0xc6), 0x3a, unchecked(0xed), unchecked(0x95), 0x0e, unchecked(0xe5), unchecked(0x85), 0x6b, 0x40, 0x21, unchecked(0x9b), 0x09, 0x19, 0x2b, 0x52, unchecked(0xde), 0x45, unchecked(0xa3), unchecked(0xfa), 0x51, unchecked(0xc2), unchecked(0xb5), unchecked(0xd1), unchecked(0x90), unchecked(0xb9), unchecked(0xf3), 0x37, unchecked(0xc1), 0x0d, unchecked(0xba), 0x41, 0x11, 0x38, 0x7b, unchecked(0xbe), unchecked(0xd0), unchecked(0xd5), 0x69, 0x36, unchecked(0xc8), 0x62, 0x1b, unchecked(0x82), unchecked(0x8f)};

		private static readonly byte[] T1 = new byte[]{unchecked(0x83), unchecked(0xf2), 0x2a, unchecked(0xeb), unchecked(0xe9), unchecked(0xbf), 0x7b, unchecked(0x9c), 0x34, unchecked(0x96), unchecked(0x8d), unchecked(0x98), unchecked(0xb9), 0x69, unchecked(0x8c), 0x29, 0x3d, unchecked(0x88), 0x68, 0x06, 0x39, 0x11, 0x4c, 0x0e, unchecked(0xa0), 0x56, 0x40, unchecked(0x92), 0x15, unchecked(0xbc), unchecked(0xb3), unchecked(0xdc), 0x6f, unchecked(0xf8), 0x26, unchecked(0xba), unchecked(0xbe), unchecked(0xbd), 0x31, unchecked(0xfb), unchecked(0xc3), unchecked(0xfe), unchecked(0x80), 0x61, unchecked(0xe1), 0x7a, 0x32, unchecked(0xd2), 0x70, 0x20, unchecked(0xa1), 0x45, unchecked(0xec), unchecked(0xd9), 0x1a, 0x5d, unchecked(0xb4), unchecked(0xd8), 0x09, unchecked(0xa5), 0x55, unchecked(0x8e), 0x37, 0x76, unchecked(0xa9), 0x67, 0x10, 0x17, 0x36, 0x65, unchecked(0xb1), unchecked(0x95), 0x62, 0x59, 0x74, unchecked(0xa3), 0x50, 0x2f, 0x4b, unchecked(0xc8), unchecked(0xd0), unchecked(0x8f), unchecked(0xcd), unchecked(0xd4), 0x3c, unchecked(0x86), 0x12, 0x1d, 0x23, unchecked(0xef), unchecked(0xf4), 0x53, 0x19, 0x35, unchecked(0xe6), 0x7f, 0x5e, unchecked(0xd6), 0x79, 0x51, 0x22, 0x14, unchecked(0xf7), 0x1e, 0x4a, 0x42, unchecked(0x9b), 0x41, 0x73, 0x2d, unchecked(0xc1), 0x5c, unchecked(0xa6), unchecked(0xa2), unchecked(0xe0), 0x2e, unchecked(0xd3), 0x28, unchecked(0xbb), unchecked(0xc9), unchecked(0xae), 0x6a, unchecked(0xd1), 0x5a, 0x30, unchecked(0x90), unchecked(0x84), unchecked(0xf9), unchecked(0xb2), 0x58, unchecked(0xcf), 0x7e, unchecked(0xc5), unchecked(0xcb), unchecked(0x97), unchecked(0xe4), 0x16, 0x6c, unchecked(0xfa), unchecked(0xb0), 0x6d, 0x1f, 0x52, unchecked(0x99), 0x0d, 0x4e, 0x03, unchecked(0x91), unchecked(0xc2), 0x4d, 0x64, 0x77, unchecked(0x9f), unchecked(0xdd), unchecked(0xc4), 0x49, unchecked(0x8a), unchecked(0x9a), 0x24, 0x38, unchecked(0xa7), 0x57, unchecked(0x85), unchecked(0xc7), 0x7c, 0x7d, unchecked(0xe7), unchecked(0xf6), unchecked(0xb7), unchecked(0xac), 0x27, 0x46, unchecked(0xde), unchecked(0xdf), 0x3b, unchecked(0xd7), unchecked(0x9e), 0x2b, 0x0b, unchecked(0xd5), 0x13, 0x75, unchecked(0xf0), 0x72, unchecked(0xb6), unchecked(0x9d), 0x1b, 0x01, 0x3f, 0x44, unchecked(0xe5), unchecked(0x87), unchecked(0xfd), 0x07, unchecked(0xf1), unchecked(0xab), unchecked(0x94), 0x18, unchecked(0xea), unchecked(0xfc), 0x3a, unchecked(0x82), 0x5f, 0x05, 0x54, unchecked(0xdb), 0x00, unchecked(0x8b), unchecked(0xe3), 0x48, 0x0c, unchecked(0xca), 0x78, unchecked(0x89), 0x0a, unchecked(0xff), 0x3e, 0x5b, unchecked(0x81), unchecked(0xee), 0x71, unchecked(0xe2), unchecked(0xda), 0x2c, unchecked(0xb8), unchecked(0xb5), unchecked(0xcc), 0x6e, unchecked(0xa8), 0x6b, unchecked(0xad), 0x60, unchecked(0xc6), 0x08, 0x04, 0x02, unchecked(0xe8), unchecked(0xf5), 0x4f, unchecked(0xa4), unchecked(0xf3), unchecked(0xc0), unchecked(0xce), 0x43, 0x25, 0x1c, 0x21, 0x33, 0x0f, unchecked(0xaf), 0x47, unchecked(0xed), 0x66, 0x63, unchecked(0x93), unchecked(0xaa)};

		private static readonly byte[] T2 = new byte[]{0x45, unchecked(0xd4), 0x0b, 0x43, unchecked(0xf1), 0x72, unchecked(0xed), unchecked(0xa4), unchecked(0xc2), 0x38, unchecked(0xe6), 0x71, unchecked(0xfd), unchecked(0xb6), 0x3a, unchecked(0x95), 0x50, 0x44, 0x4b, unchecked(0xe2), 0x74, 0x6b, 0x1e, 0x11, 0x5a, unchecked(0xc6), unchecked(0xb4), unchecked(0xd8), unchecked(0xa5), unchecked(0x8a), 0x70, unchecked(0xa3), unchecked(0xa8), unchecked(0xfa), 0x05, unchecked(0xd9), unchecked(0x97), 0x40, unchecked(0xc9), unchecked(0x90), unchecked(0x98), unchecked(0x8f), unchecked(0xdc), 0x12, 0x31, 0x2c, 0x47, 0x6a, unchecked(0x99), unchecked(0xae), unchecked(0xc8), 0x7f, unchecked(0xf9), 0x4f, 0x5d, unchecked(0x96), 0x6f, unchecked(0xf4), unchecked(0xb3), 0x39, 0x21, unchecked(0xda), unchecked(0x9c), unchecked(0x85), unchecked(0x9e), 0x3b, unchecked(0xf0), unchecked(0xbf), unchecked(0xef), 0x06, unchecked(0xee), unchecked(0xe5), 0x5f, 0x20, 0x10, unchecked(0xcc), 0x3c, 0x54, 0x4a, 0x52, unchecked(0x94), 0x0e, unchecked(0xc0), 0x28, unchecked(0xf6), 0x56, 0x60, unchecked(0xa2), unchecked(0xe3), 0x0f, unchecked(0xec), unchecked(0x9d), 0x24, unchecked(0x83), 0x7e, unchecked(0xd5), 0x7c, unchecked(0xeb), 0x18, unchecked(0xd7), unchecked(0xcd), unchecked(0xdd), 0x78, unchecked(0xff), unchecked(0xdb), unchecked(0xa1), 0x09, unchecked(0xd0), 0x76, unchecked(0x84), 0x75, unchecked(0xbb), 0x1d, 0x1a, 0x2f, unchecked(0xb0), unchecked(0xfe), unchecked(0xd6), 0x34, 0x63, 0x35, unchecked(0xd2), 0x2a, 0x59, 0x6d, 0x4d, 0x77, unchecked(0xe7), unchecked(0x8e), 0x61, unchecked(0xcf), unchecked(0x9f), unchecked(0xce), 0x27, unchecked(0xf5), unchecked(0x80), unchecked(0x86), unchecked(0xc7), unchecked(0xa6), unchecked(0xfb), unchecked(0xf8), unchecked(0x87), unchecked(0xab), 0x62, 0x3f, unchecked(0xdf), 0x48, 0x00, 0x14, unchecked(0x9a), unchecked(0xbd), 0x5b, 0x04, unchecked(0x92), 0x02, 0x25, 0x65, 0x4c, 0x53, 0x0c, unchecked(0xf2), 0x29, unchecked(0xaf), 0x17, 0x6c, 0x41, 0x30, unchecked(0xe9), unchecked(0x93), 0x55, unchecked(0xf7), unchecked(0xac), 0x68, 0x26, unchecked(0xc4), 0x7d, unchecked(0xca), 0x7a, 0x3e, unchecked(0xa0), 0x37, 0x03, unchecked(0xc1), 0x36, 0x69, 0x66, 0x08, 0x16, unchecked(0xa7), unchecked(0xbc), unchecked(0xc5), unchecked(0xd3), 0x22, unchecked(0xb7), 0x13, 0x46, 0x32, unchecked(0xe8), 0x57, unchecked(0x88), 0x2b, unchecked(0x81), unchecked(0xb2), 0x4e, 0x64, 0x1c, unchecked(0xaa), unchecked(0x91), 0x58, 0x2e, unchecked(0x9b), 0x5c, 0x1b, 0x51, 0x73, 0x42, 0x23, 0x01, 0x6e, unchecked(0xf3), 0x0d, unchecked(0xbe), 0x3d, 0x0a, 0x2d, 0x1f, 0x67, 0x33, 0x19, 0x7b, 0x5e, unchecked(0xea), unchecked(0xde), unchecked(0x8b), unchecked(0xcb), unchecked(0xa9), unchecked(0x8c), unchecked(0x8d), unchecked(0xad), 0x49, unchecked(0x82), unchecked(0xe4), unchecked(0xba), unchecked(0xc3), 0x15, unchecked(0xd1), unchecked(0xe0), unchecked(0x89), unchecked(0xfc), unchecked(0xb1), unchecked(0xb9), unchecked(0xb5), 0x07, 0x79, unchecked(0xb8), unchecked(0xe1)};

		private static readonly byte[] T3 = new byte[]{unchecked(0xb2), unchecked(0xb6), 0x23, 0x11, unchecked(0xa7), unchecked(0x88), unchecked(0xc5), unchecked(0xa6), 0x39, unchecked(0x8f), unchecked(0xc4), unchecked(0xe8), 0x73, 0x22, 0x43, unchecked(0xc3), unchecked(0x82), 0x27, unchecked(0xcd), 0x18, 0x51, 0x62, 0x2d, unchecked(0xf7), 0x5c, 0x0e, 0x3b, unchecked(0xfd), unchecked(0xca), unchecked(0x9b), 0x0d, 0x0f, 0x79, unchecked(0x8c), 0x10, 0x4c, 0x74, 0x1c, 0x0a, unchecked(0x8e), 0x7c, unchecked(0x94), 0x07, unchecked(0xc7), 0x5e, 0x14, unchecked(0xa1), 0x21, 0x57, 0x50, 0x4e, unchecked(0xa9), unchecked(0x80), unchecked(0xd9), unchecked(0xef), 0x64, 0x41, unchecked(0xcf), 0x3c, unchecked(0xee), 0x2e, 0x13, 0x29, unchecked(0xba), 0x34, 0x5a, unchecked(0xae), unchecked(0x8a), 0x61, 0x33, 0x12, unchecked(0xb9), 0x55, unchecked(0xa8), 0x15, 0x05, unchecked(0xf6), 0x03, 0x06, 0x49, unchecked(0xb5), 0x25, 0x09, 0x16, 0x0c, 0x2a, 0x38, unchecked(0xfc), 0x20, unchecked(0xf4), unchecked(0xe5), 0x7f, unchecked(0xd7), 0x31, 0x2b, 0x66, 0x6f, unchecked(0xff), 0x72, unchecked(0x86), unchecked(0xf0), unchecked(0xa3), 0x2f, 0x78, 0x00, unchecked(0xbc), unchecked(0xcc), unchecked(0xe2), unchecked(0xb0), unchecked(0xf1), 0x42, unchecked(0xb4), 0x30, 0x5f, 0x60, 0x04, unchecked(0xec), unchecked(0xa5), unchecked(0xe3), unchecked(0x8b), unchecked(0xe7), 0x1d, unchecked(0xbf), unchecked(0x84), 0x7b, unchecked(0xe6), unchecked(0x81), unchecked(0xf8), unchecked(0xde), unchecked(0xd8), unchecked(0xd2), 0x17, unchecked(0xce), 0x4b, 0x47, unchecked(0xd6), 0x69, 0x6c, 0x19, unchecked(0x99), unchecked(0x9a), 0x01, unchecked(0xb3), unchecked(0x85), unchecked(0xb1), unchecked(0xf9), 0x59, unchecked(0xc2), 0x37, unchecked(0xe9), unchecked(0xc8), unchecked(0xa0), unchecked(0xed), 0x4f, unchecked(0x89), 0x68, 0x6d, unchecked(0xd5), 0x26, unchecked(0x91), unchecked(0x87), 0x58, unchecked(0xbd), unchecked(0xc9), unchecked(0x98), unchecked(0xdc), 0x75, unchecked(0xc0), 0x76, unchecked(0xf5), 0x67, 0x6b, 0x7e, unchecked(0xeb), 0x52, unchecked(0xcb), unchecked(0xd1), 0x5b, unchecked(0x9f), 0x0b, unchecked(0xdb), 0x40, unchecked(0x92), 0x1a, unchecked(0xfa), unchecked(0xac), unchecked(0xe4), unchecked(0xe1), 0x71, 0x1f, 0x65, unchecked(0x8d), unchecked(0x97), unchecked(0x9e), unchecked(0x95), unchecked(0x90), 0x5d, unchecked(0xb7), unchecked(0xc1), unchecked(0xaf), 0x54, unchecked(0xfb), 0x02, unchecked(0xe0), 0x35, unchecked(0xbb), 0x3a, 0x4d, unchecked(0xad), 0x2c, 0x3d, 0x56, 0x08, 0x1b, 0x4a, unchecked(0x93), 0x6a, unchecked(0xab), unchecked(0xb8), 0x7a, unchecked(0xf2), 0x7d, unchecked(0xda), 0x3f, unchecked(0xfe), 0x3e, unchecked(0xbe), unchecked(0xea), unchecked(0xaa), 0x44, unchecked(0xc6), unchecked(0xd0), 0x36, 0x48, 0x70, unchecked(0x96), 0x77, 0x24, 0x53, unchecked(0xdf), unchecked(0xf3), unchecked(0x83), 0x28, 0x32, 0x45, 0x1e, unchecked(0xa4), unchecked(0xd3), unchecked(0xa2), 0x46, 0x6e, unchecked(0x9c), unchecked(0xdd), 0x63, unchecked(0xd4), unchecked(0x9d)};
	}

}