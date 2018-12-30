using BouncyCastle.Core.Port.java.lang;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.qtesla
{
	public class Pack
	{

		/// <summary>
		///*****************************************************************************************************************************************************
		/// Description:	Encode Private Key for Heuristic qTESLA Security Category-1
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">                Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns> none
		/// ****************************************************************************************************************************************************** </returns>
		public static void encodePrivateKeyI(byte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, byte[] seed, int seedOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_I; i += 4)
			{

				privateKey[j + 0] = (byte)secretPolynomial[i + 0];
				privateKey[j + 1] = (byte)(((secretPolynomial[i + 0] >> 8) & 0x03) | (secretPolynomial[i + 1] << 2));
				privateKey[j + 2] = (byte)(((secretPolynomial[i + 1] >> 6) & 0x0F) | (secretPolynomial[i + 2] << 4));
				privateKey[j + 3] = (byte)(((secretPolynomial[i + 2] >> 4) & 0x3F) | (secretPolynomial[i + 3] << 6));
				privateKey[j + 4] = (byte)(secretPolynomial[i + 3] >> 2);

				j += 5;

			}

			for (int i = 0; i < Parameter.N_I; i += 4)
			{

				privateKey[j + 0] = (byte)errorPolynomial[i + 0];
				privateKey[j + 1] = (byte)(((errorPolynomial[i + 0] >> 8) & 0x03) | (errorPolynomial[i + 1] << 2));
				privateKey[j + 2] = (byte)(((errorPolynomial[i + 1] >> 6) & 0x0F) | (errorPolynomial[i + 2] << 4));
				privateKey[j + 3] = (byte)(((errorPolynomial[i + 2] >> 4) & 0x3F) | (errorPolynomial[i + 3] << 6));
				privateKey[j + 4] = (byte)(errorPolynomial[i + 3] >> 2);

				j += 5;

			}

			JavaSystem.arraycopy(seed, seedOffset, privateKey, Parameter.N_I * Parameter.S_BIT_I * 2 / Byte.SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///***********************************************************************************************************************************************************
		/// Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">                Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************ </returns>
		public static void encodePrivateKeyIIISize(byte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, byte[] seed, int seedOffset)
		{

			for (int i = 0; i < Parameter.N_III_SIZE; i++)
			{

				privateKey[i] = (byte)secretPolynomial[i];

			}

			for (int i = 0; i < Parameter.N_III_SIZE; i++)
			{

				privateKey[Parameter.N_III_SIZE + i] = (byte)errorPolynomial[i];

			}

			JavaSystem.arraycopy(seed, seedOffset, privateKey, Parameter.N_III_SIZE * Parameter.S_BIT_III_SIZE * 2 / Byte.SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///*********************************************************************************************************************************************************************************
		/// Description:	Encode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">                Starting Point of the Kappa-Bit Seed
		/// </param>
		/// <returns> none
		/// ********************************************************************************************************************************************************************************** </returns>
		public static void encodePrivateKeyIIISpeed(byte[] privateKey, int[] secretPolynomial, int[] errorPolynomial, byte[] seed, int seedOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
			{

				privateKey[j + 0] = (byte)secretPolynomial[i + 0];
				privateKey[j + 1] = (byte)(((secretPolynomial[i + 0] >> 8) & 0x01) | (secretPolynomial[i + 1] << 1));
				privateKey[j + 2] = (byte)(((secretPolynomial[i + 1] >> 7) & 0x03) | (secretPolynomial[i + 2] << 2));
				privateKey[j + 3] = (byte)(((secretPolynomial[i + 2] >> 6) & 0x07) | (secretPolynomial[i + 3] << 3));
				privateKey[j + 4] = (byte)(((secretPolynomial[i + 3] >> 5) & 0x0F) | (secretPolynomial[i + 4] << 4));
				privateKey[j + 5] = (byte)(((secretPolynomial[i + 4] >> 4) & 0x1F) | (secretPolynomial[i + 5] << 5));
				privateKey[j + 6] = (byte)(((secretPolynomial[i + 5] >> 3) & 0x3F) | (secretPolynomial[i + 6] << 6));
				privateKey[j + 7] = (byte)(((secretPolynomial[i + 6] >> 2) & 0x7F) | (secretPolynomial[i + 7] << 7));
				privateKey[j + 8] = (byte)(secretPolynomial[i + 7] >> 1);

				j += 9;

			}

			for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
			{

				privateKey[j + 0] = (byte)errorPolynomial[i + 0];
				privateKey[j + 1] = (byte)(((errorPolynomial[i + 0] >> 8) & 0x01) | (errorPolynomial[i + 1] << 1));
				privateKey[j + 2] = (byte)(((errorPolynomial[i + 1] >> 7) & 0x03) | (errorPolynomial[i + 2] << 2));
				privateKey[j + 3] = (byte)(((errorPolynomial[i + 2] >> 6) & 0x07) | (errorPolynomial[i + 3] << 3));
				privateKey[j + 4] = (byte)(((errorPolynomial[i + 3] >> 5) & 0x0F) | (errorPolynomial[i + 4] << 4));
				privateKey[j + 5] = (byte)(((errorPolynomial[i + 4] >> 4) & 0x1F) | (errorPolynomial[i + 5] << 5));
				privateKey[j + 6] = (byte)(((errorPolynomial[i + 5] >> 3) & 0x3F) | (errorPolynomial[i + 6] << 6));
				privateKey[j + 7] = (byte)(((errorPolynomial[i + 6] >> 2) & 0x7F) | (errorPolynomial[i + 7] << 7));
				privateKey[j + 8] = (byte)(errorPolynomial[i + 7] >> 1);

				j += 9;

			}

			JavaSystem.arraycopy(seed, seedOffset, privateKey, Parameter.N_III_SPEED * Parameter.S_BIT_III_SPEED * 2 / Byte.SIZE, Polynomial.SEED * 2);

		}

		/// <summary>
		///*****************************************************************************************************************************
		/// Description:	Decode Private Key for Heuristic qTESLA Security Category-1
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">                Private Key
		/// </param>
		/// <returns> none
		/// ****************************************************************************************************************************** </returns>
		public static void decodePrivateKeyI(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, byte[] privateKey)
		{

			int j = 0;
			int temporary = 0;

			for (int i = 0; i < Parameter.N_I; i += 4)
			{

				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0] = (short)temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 30) >> 22;
				secretPolynomial[i + 0] |= (short)temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 2;
				secretPolynomial[i + 1] = (short)temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 28) >> 22;
				secretPolynomial[i + 1] |= (short)temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 4;
				secretPolynomial[i + 2] = (short)temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 26) >> 22;
				secretPolynomial[i + 2] |= (short)temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 6;
				secretPolynomial[i + 3] = (short)temporary;
				temporary = privateKey[j + 4];
				temporary = (short)temporary << 2;
				secretPolynomial[i + 3] |= (short)temporary;

				j += 5;

			}

			for (int i = 0; i < Parameter.N_I; i += 4)
			{

				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0] = (short)temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 30) >> 22;
				errorPolynomial[i + 0] |= (short)temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 2;
				errorPolynomial[i + 1] = (short)temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 28) >> 22;
				errorPolynomial[i + 1] |= (short)temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 4;
				errorPolynomial[i + 2] = (short)temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 26) >> 22;
				errorPolynomial[i + 2] |= (short)temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 6;
				errorPolynomial[i + 3] = (short)temporary;
				temporary = privateKey[j + 4];
				temporary = (short)temporary << 2;
				errorPolynomial[i + 3] |= (short)temporary;

				j += 5;

			}

			JavaSystem.arraycopy(privateKey, Parameter.N_I * Parameter.S_BIT_I * 2 / Byte.SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///***********************************************************************************************************************************
		/// Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">                Private Key
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************ </returns>
		public static void decodePrivateKeyIIISize(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, byte[] privateKey)
		{

			for (int i = 0; i < Parameter.N_III_SIZE; i++)
			{

				secretPolynomial[i] = privateKey[i];

			}

			for (int i = 0; i < Parameter.N_III_SIZE; i++)
			{

				errorPolynomial[i] = privateKey[Parameter.N_III_SIZE + i];

			}

			JavaSystem.arraycopy(privateKey, Parameter.N_III_SIZE * Parameter.S_BIT_III_SIZE * 2 / Byte.SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///************************************************************************************************************************************
		/// Description:	Decode Private Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="privateKey">                Private Key
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************* </returns>
		public static void decodePrivateKeyIIISpeed(byte[] seed, short[] secretPolynomial, short[] errorPolynomial, byte[] privateKey)
		{

			int j = 0;
			int temporary = 0;

			for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
			{

				temporary = privateKey[j + 0] & 0xFF;
				secretPolynomial[i + 0] = (short)temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				secretPolynomial[i + 0] |= (short)temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				secretPolynomial[i + 1] = (short)temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				secretPolynomial[i + 1] |= (short)temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				secretPolynomial[i + 2] = (short)temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				secretPolynomial[i + 2] |= (short)temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				secretPolynomial[i + 3] = (short)temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				secretPolynomial[i + 3] |= (short)temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				secretPolynomial[i + 4] = (short)temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				secretPolynomial[i + 4] |= (short)temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				secretPolynomial[i + 5] = (short)temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				secretPolynomial[i + 5] |= (short)temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				secretPolynomial[i + 6] = (short)temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				secretPolynomial[i + 6] |= (short)temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				secretPolynomial[i + 7] = (short)temporary;
				temporary = privateKey[j + 8];
				temporary = (short)temporary << 1;
				secretPolynomial[i + 7] |= (short)temporary;

				j += 9;

			}

			for (int i = 0; i < Parameter.N_III_SPEED; i += 8)
			{

				temporary = privateKey[j + 0] & 0xFF;
				errorPolynomial[i + 0] = (short)temporary;
				temporary = privateKey[j + 1] & 0xFF;
				temporary = (temporary << 31) >> 23;
				errorPolynomial[i + 0] |= (short)temporary;

				temporary = privateKey[j + 1] & 0xFF;
				temporary = temporary >> 1;
				errorPolynomial[i + 1] = (short)temporary;
				temporary = privateKey[j + 2] & 0xFF;
				temporary = (temporary << 30) >> 23;
				errorPolynomial[i + 1] |= (short)temporary;

				temporary = privateKey[j + 2] & 0xFF;
				temporary = temporary >> 2;
				errorPolynomial[i + 2] = (short)temporary;
				temporary = privateKey[j + 3] & 0xFF;
				temporary = (temporary << 29) >> 23;
				errorPolynomial[i + 2] |= (short)temporary;

				temporary = privateKey[j + 3] & 0xFF;
				temporary = temporary >> 3;
				errorPolynomial[i + 3] = (short)temporary;
				temporary = privateKey[j + 4] & 0xFF;
				temporary = (temporary << 28) >> 23;
				errorPolynomial[i + 3] |= (short)temporary;

				temporary = privateKey[j + 4] & 0xFF;
				temporary = temporary >> 4;
				errorPolynomial[i + 4] = (short)temporary;
				temporary = privateKey[j + 5] & 0xFF;
				temporary = (temporary << 27) >> 23;
				errorPolynomial[i + 4] |= (short)temporary;

				temporary = privateKey[j + 5] & 0xFF;
				temporary = temporary >> 5;
				errorPolynomial[i + 5] = (short)temporary;
				temporary = privateKey[j + 6] & 0xFF;
				temporary = (temporary << 26) >> 23;
				errorPolynomial[i + 5] |= (short)temporary;

				temporary = privateKey[j + 6] & 0xFF;
				temporary = temporary >> 6;
				errorPolynomial[i + 6] = (short)temporary;
				temporary = privateKey[j + 7] & 0xFF;
				temporary = (temporary << 25) >> 23;
				errorPolynomial[i + 6] |= (short)temporary;

				temporary = privateKey[j + 7] & 0xFF;
				temporary = temporary >> 7;
				errorPolynomial[i + 7] = (short)temporary;
				temporary = privateKey[j + 8];
				temporary = (short)temporary << 1;
				errorPolynomial[i + 7] |= (short)temporary;

				j += 9;

			}

			JavaSystem.arraycopy(privateKey, Parameter.N_III_SPEED * Parameter.S_BIT_III_SPEED * 2 / Byte.SIZE, seed, 0, Polynomial.SEED * 2);

		}

		/// <summary>
		///******************************************************************************************************************************************************************
		/// Description:	Pack Private Key for Provably-Secure qTESLA Security Category-1 and Security Category-3
		/// </summary>
		/// <param name="privateKey">                Private Key </param>
		/// <param name="secretPolynomial">        Coefficients of the Secret Polynomial </param>
		/// <param name="errorPolynomial">            Coefficients of the Error Polynomial </param>
		/// <param name="seed">                    Kappa-Bit Seed </param>
		/// <param name="seedOffset">                Starting Point of the Kappa-Bit Seed </param>
		/// <param name="n">                        Polynomial Degree </param>
		/// <param name="k">                        Number of Ring-Learning-With-Errors Samples
		/// </param>
		/// <returns> none
		/// ******************************************************************************************************************************************************************* </returns>
		public static void packPrivateKey(byte[] privateKey, long[] secretPolynomial, long[] errorPolynomial, byte[] seed, int seedOffset, int n, int k)
		{

			for (int i = 0; i < n; i++)
			{

				privateKey[i] = (byte)secretPolynomial[i];

			}

			for (int j = 0; j < k; j++)
			{

				for (int i = 0; i < n; i++)
				{

					privateKey[n + j * n + i] = (byte)errorPolynomial[j * n + i];

				}

			}

			JavaSystem.arraycopy(seed, seedOffset, privateKey, n + k * n, Polynomial.SEED * 2);

		}

		/// <summary>
		///************************************************************************************************************************************************
		/// Description:	Encode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="publicKey">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="qLogarithm">            q <= 2 ^ qLogartihm
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************* </returns>
		public static void encodePublicKey(byte[] publicKey, int[] T, byte[] seedA, int seedAOffset, int n, int qLogarithm)
		{

			int j = 0;

			for (int i = 0; i < n * qLogarithm / (sizeof(int) * 8); i += qLogarithm)
			{

				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 23)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 9) | (T[j + 2] << 14)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 18) | (T[j + 3] << 5) | (T[j + 4] << 28)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 3), (int)((T[j + 4] >> 4) | (T[j + 5] << 19)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 4), (int)((T[j + 5] >> 13) | (T[j + 6] << 10)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 5), (int)((T[j + 6] >> 22) | (T[j + 7] << 1) | (T[j + 8] << 24)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 6), (int)((T[j + 8] >> 8) | (T[j + 9] << 15)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 7), (int)((T[j + 9] >> 17) | (T[j + 10] << 6) | (T[j + 11] << 29)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 8), (int)((T[j + 11] >> 3) | (T[j + 12] << 20)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 9), (int)((T[j + 12] >> 12) | (T[j + 13] << 11)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 10), (int)((T[j + 13] >> 21) | (T[j + 14] << 2) | (T[j + 15] << 25)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 11), (int)((T[j + 15] >> 7) | (T[j + 16] << 16)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 12), (int)((T[j + 16] >> 16) | (T[j + 17] << 7) | (T[j + 18] << 30)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 13), (int)((T[j + 18] >> 2) | (T[j + 19] << 21)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 14), (int)((T[j + 19] >> 11) | (T[j + 20] << 12)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 15), (int)((T[j + 20] >> 20) | (T[j + 21] << 3) | (T[j + 22] << 26)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 16), (int)((T[j + 22] >> 6) | (T[j + 23] << 17)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 17), (int)((T[j + 23] >> 15) | (T[j + 24] << 8) | (T[j + 25] << 31)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 18), (int)((T[j + 25] >> 1) | (T[j + 26] << 22)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 19), (int)((T[j + 26] >> 10) | (T[j + 27] << 13)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 20), (int)((T[j + 27] >> 19) | (T[j + 28] << 4) | (T[j + 29] << 27)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 21), (int)((T[j + 29] >> 5) | (T[j + 30] << 18)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 22), (int)((T[j + 30] >> 14) | (T[j + 31] << 9)));

				j += (sizeof(int) * 8);

			}

			JavaSystem.arraycopy(seedA, seedAOffset, publicKey, n * qLogarithm / Byte.SIZE, Polynomial.SEED);

		}

		/// <summary>
		///****************************************************************************************************************************************************
		/// Description:	Encode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKey">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A
		/// </param>
		/// <returns> none
		/// ***************************************************************************************************************************************************** </returns>
		public static void encodePublicKeyIIISpeed(byte[] publicKey, int[] T, byte[] seedA, int seedAOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / (sizeof(int) * 8); i += (Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE))
			{

				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 24)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 8) | (T[j + 2] << 16)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 16) | (T[j + 3] << 8)));

				j += (sizeof(int) * 8) / Byte.SIZE;

			}

			JavaSystem.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE, Polynomial.SEED);

		}

		/// <summary>
		///*****************************************************************************************************************************************************
		/// Description:	Encode Public Key for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="publicKey">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A
		/// </param>
		/// <returns> none
		/// ****************************************************************************************************************************************************** </returns>
		public static void encodePublicKeyIP(byte[] publicKey, long[] T, byte[] seedA, int seedAOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / (sizeof(int) * 8); i += Parameter.Q_LOGARITHM_I_P)
			{

				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(T[j + 0] | (T[j + 1] << 29)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)((T[j + 1] >> 3) | (T[j + 2] << 26)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)((T[j + 2] >> 6) | (T[j + 3] << 23)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 3), (int)((T[j + 3] >> 9) | (T[j + 4] << 20)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 4), (int)((T[j + 4] >> 12) | (T[j + 5] << 17)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 5), (int)((T[j + 5] >> 15) | (T[j + 6] << 14)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 6), (int)((T[j + 6] >> 18) | (T[j + 7] << 11)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 7), (int)((T[j + 7] >> 21) | (T[j + 8] << 8)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 8), (int)((T[j + 8] >> 24) | (T[j + 9] << 5)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 9), (int)((T[j + 9] >> 27) | (T[j + 10] << 2) | (T[j + 11] << 31)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 10), (int)((T[j + 11] >> 1) | (T[j + 12] << 28)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 11), (int)((T[j + 12] >> 4) | (T[j + 13] << 25)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 12), (int)((T[j + 13] >> 7) | (T[j + 14] << 22)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 13), (int)((T[j + 14] >> 10) | (T[j + 15] << 19)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 14), (int)((T[j + 15] >> 13) | (T[j + 16] << 16)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 15), (int)((T[j + 16] >> 16) | (T[j + 17] << 13)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 16), (int)((T[j + 17] >> 19) | (T[j + 18] << 10)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 17), (int)((T[j + 18] >> 22) | (T[j + 19] << 7)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 18), (int)((T[j + 19] >> 25) | (T[j + 20] << 4)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 19), (int)((T[j + 20] >> 28) | (T[j + 21] << 1) | (T[j + 22] << 30)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 20), (int)((T[j + 22] >> 2) | (T[j + 23] << 27)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 21), (int)((T[j + 23] >> 5) | (T[j + 24] << 24)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 22), (int)((T[j + 24] >> 8) | (T[j + 25] << 21)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 23), (int)((T[j + 25] >> 11) | (T[j + 26] << 18)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 24), (int)((T[j + 26] >> 14) | (T[j + 27] << 15)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 25), (int)((T[j + 27] >> 17) | (T[j + 28] << 12)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 26), (int)((T[j + 28] >> 20) | (T[j + 29] << 9)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 27), (int)((T[j + 29] >> 23) | (T[j + 30] << 6)));
				CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + 28), (int)((T[j + 30] >> 26) | (T[j + 31] << 3)));

				j += (sizeof(int) * 8);

			}

			JavaSystem.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Byte.SIZE, Polynomial.SEED);

		}

		/// <summary>
		///***********************************************************************************************************************************************************************************
		/// Description:	Encode Public Key for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="publicKey">            Public Key </param>
		/// <param name="T">                    T_1, ..., T_k </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials a_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************************************ </returns>
		public static void encodePublicKeyIIIP(byte[] publicKey, long[] T, byte[] seedA, int seedAOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / (sizeof(int) * 8); i += Parameter.Q_LOGARITHM_III_P)
			{

				for (int index = 0; index < Parameter.Q_LOGARITHM_III_P; index++)
				{

					CommonFunction.store32(publicKey, (sizeof(int) * 8) / Byte.SIZE * (i + index), (int)((T[j + index] >> index) | (T[j + index + 1] << (Parameter.Q_LOGARITHM_III_P - index))));

				}

				j += (sizeof(int) * 8);

			}

			JavaSystem.arraycopy(seedA, seedAOffset, publicKey, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Byte.SIZE, Polynomial.SEED);

		}

		/// <summary>
		///**************************************************************************************************************************************
		/// Description:	Decode Public Key for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="publicKey">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInput">        Public Key to be Decoded </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="qLogarithm">            q <= 2 ^ qLogartihm
		/// </param>
		/// <returns> none
		/// *************************************************************************************************************************************** </returns>
		public static void decodePublicKey(int[] publicKey, byte[] seedA, int seedAOffset, byte[] publicKeyInput, int n, int qLogarithm)
		{

			int j = 0;

			int mask = (1 << qLogarithm) - 1;

			for (int i = 0; i < n; i += (sizeof(int) * 8))
			{

				publicKey[i + 0] = CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) & mask;

				publicKey[i + 1] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 23)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 9)) & mask;

				publicKey[i + 2] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 14)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 18)) & mask;

				publicKey[i + 3] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 5)) & mask;

				publicKey[i + 4] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 28)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 4)) & mask;

				publicKey[i + 5] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 3)) >> 19)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 13)) & mask;

				publicKey[i + 6] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 4)) >> 10)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 22)) & mask;

				publicKey[i + 7] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 1)) & mask;

				publicKey[i + 8] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 24)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 8)) & mask;

				publicKey[i + 9] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 6)) >> 15)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 17)) & mask;

				publicKey[i + 10] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 6)) & mask;

				publicKey[i + 11] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 29)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 3)) & mask;

				publicKey[i + 12] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 8)) >> 20)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 12)) & mask;

				publicKey[i + 13] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 11)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 10)) << 21)) & mask;

				publicKey[i + 14] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 2)) & mask;

				publicKey[i + 15] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 25)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 11)) << 7)) & mask;

				publicKey[i + 16] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 11)) >> 16)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 12)) << 16)) & mask;

				publicKey[i + 17] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 12)) >> 7)) & mask;

				publicKey[i + 18] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 12)) >> 30)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 13)) << 2)) & mask;

				publicKey[i + 19] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 13)) >> 21)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 14)) << 11)) & mask;

				publicKey[i + 20] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 14)) >> 12)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 15)) << 20)) & mask;

				publicKey[i + 21] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 15)) >> 3)) & mask;

				publicKey[i + 22] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 15)) >> 26)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 16)) << 6)) & mask;

				publicKey[i + 23] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 16)) >> 17)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 17)) << 15)) & mask;

				publicKey[i + 24] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 17)) >> 8)) & mask;

				publicKey[i + 25] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 17)) >> 31)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 18)) << 1)) & mask;

				publicKey[i + 26] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 18)) >> 22)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 19)) << 10)) & mask;

				publicKey[i + 27] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 19)) >> 13)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 20)) << 19)) & mask;

				publicKey[i + 28] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 20)) >> 4)) & mask;

				publicKey[i + 29] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 20)) >> 27)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 21)) << 5)) & mask;

				publicKey[i + 30] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 21)) >> 18)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 22)) << 14)) & mask;

				publicKey[i + 31] = (int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 22)) >> 9);

				j += qLogarithm;

			}

			JavaSystem.arraycopy(publicKeyInput, n * qLogarithm / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///***********************************************************************************************************************************************
		/// Description:	Decode Public Key for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="publicKey">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInput">        Public Key to be Decoded
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************ </returns>
		public static void decodePublicKeyIIISpeed(int[] publicKey, byte[] seedA, int seedAOffset, byte[] publicKeyInput)
		{

			int j = 0;

			int mask = (1 << Parameter.Q_LOGARITHM_III_SPEED) - 1;

			for (int i = 0; i < Parameter.N_III_SPEED; i += (sizeof(int) * 8) / Byte.SIZE)
			{

				publicKey[i + 0] = CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) & mask;

				publicKey[i + 1] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 24)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 8)) & mask;

				publicKey[i + 2] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 16)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 16)) & mask;

				publicKey[i + 3] = (int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 8);

				j += Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE;

			}

			JavaSystem.arraycopy(publicKeyInput, Parameter.N_III_SPEED * Parameter.Q_LOGARITHM_III_SPEED / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///**********************************************************************************************************************************************************
		/// Description:	Decode Public Key for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="publicKey">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInput">        Public Key to be Decoded
		/// </param>
		/// <returns> none
		/// *********************************************************************************************************************************************************** </returns>
		public static void decodePublicKeyIP(int[] publicKey, byte[] seedA, int seedAOffset, byte[] publicKeyInput)
		{

			int j = 0;

			int mask = (1 << Parameter.Q_LOGARITHM_I_P) - 1;

			for (int i = 0; i < Parameter.N_I_P * Parameter.K_I_P; i += (sizeof(int) * 8))
			{

				publicKey[i + 0] = CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) & mask;

				publicKey[i + 1] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 29)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 3)) & mask;

				publicKey[i + 2] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 26)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 6)) & mask;

				publicKey[i + 3] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 23)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 9)) & mask;

				publicKey[i + 4] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 3)) >> 20)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 12)) & mask;

				publicKey[i + 5] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 4)) >> 17)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 15)) & mask;

				publicKey[i + 6] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 14)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 18)) & mask;

				publicKey[i + 7] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 6)) >> 11)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 21)) & mask;

				publicKey[i + 8] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 8)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 24)) & mask;

				publicKey[i + 9] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 8)) >> 5)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 27)) & mask;

				publicKey[i + 10] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 2)) & mask;

				publicKey[i + 11] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 31)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 10)) << 1)) & mask;

				publicKey[i + 12] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 28)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 11)) << 4)) & mask;

				publicKey[i + 13] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 11)) >> 25)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 12)) << 7)) & mask;

				publicKey[i + 14] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 12)) >> 22)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 13)) << 10)) & mask;

				publicKey[i + 15] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 13)) >> 19)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 14)) << 13)) & mask;

				publicKey[i + 16] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 14)) >> 16)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 15)) << 16)) & mask;

				publicKey[i + 17] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 15)) >> 13)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 16)) << 19)) & mask;

				publicKey[i + 18] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 16)) >> 10)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 17)) << 22)) & mask;

				publicKey[i + 19] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 17)) >> 7)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 18)) << 25)) & mask;

				publicKey[i + 20] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 18)) >> 4)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 19)) << 28)) & mask;

				publicKey[i + 21] = ((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 19)) >> 1)) & mask;

				publicKey[i + 22] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 19)) >> 30)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 20)) << 2)) & mask;

				publicKey[i + 23] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 20)) >> 27)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 21)) << 5)) & mask;

				publicKey[i + 24] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 21)) >> 24)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 22)) << 8)) & mask;

				publicKey[i + 25] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 22)) >> 21)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 23)) << 11)) & mask;

				publicKey[i + 26] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 23)) >> 18)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 24)) << 14)) & mask;

				publicKey[i + 27] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 24)) >> 15)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 25)) << 17)) & mask;

				publicKey[i + 28] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 25)) >> 12)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 26)) << 20)) & mask;

				publicKey[i + 29] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 26)) >> 9)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 27)) << 23)) & mask;

				publicKey[i + 30] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 27)) >> 6)) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 28)) << 26)) & mask;

				publicKey[i + 31] = (int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + 28)) >> 3);

				j += Parameter.Q_LOGARITHM_I_P;

			}

			JavaSystem.arraycopy(publicKeyInput, Parameter.N_I_P * Parameter.K_I_P * Parameter.Q_LOGARITHM_I_P / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

		}

		/// <summary>
		///**************************************************************************************************************************************************************
		/// Description:	Decode Public Key for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="publicKey">            Decoded Public Key </param>
		/// <param name="seedA">                Seed Used to Generate the Polynomials A_i for i = 1, ..., k </param>
		/// <param name="seedAOffset">            Starting Point of the Seed A </param>
		/// <param name="publicKeyInput">        Public Key to be Decoded
		/// </param>
		/// <returns> none
		/// *************************************************************************************************************************************************************** </returns>
		public static void decodePublicKeyIIIP(int[] publicKey, byte[] seedA, int seedAOffset, byte[] publicKeyInput)
		{

			int j = 0;

			int mask = unchecked((1 << Parameter.Q_LOGARITHM_III_P) - 1);

			for (int i = 0; i < Parameter.N_III_P * Parameter.K_III_P; i += (sizeof(int) * 8))
			{

				publicKey[i] = CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * j) & mask;

				for (int index = 1; index < Parameter.Q_LOGARITHM_III_P; index++)
				{

					publicKey[i + index] = (((int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + index - 1)) >> ((sizeof(int) * 8) - index))) | (CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + index)) << index)) & mask;

				}

				publicKey[i + Parameter.Q_LOGARITHM_III_P] = (int)((uint)CommonFunction.load32(publicKeyInput, (sizeof(int) * 8) / Byte.SIZE * (j + Parameter.Q_LOGARITHM_III_P - 1)) >> 1);

				j += Parameter.Q_LOGARITHM_III_P;

			}

			JavaSystem.arraycopy(publicKeyInput, Parameter.N_III_P * Parameter.K_III_P * Parameter.Q_LOGARITHM_III_P / Byte.SIZE, seedA, seedAOffset, Polynomial.SEED);

		}


		/// <summary>
		///*************************************************************************************************************************************************************************************************************
		/// Description:	Encode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z"> </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="d">                    Number of Rounded Bits
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************************************************************** </returns>
		public static void encodeSignature(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z, int n, int d)
		{

			int j = 0;

			for (int i = 0; i < (n * d / (sizeof(int) * 8)); i += d)
			{

				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 21) - 1))) | (Z[j + 1] << 21)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)((((int)((uint)Z[j + 1] >> 11)) & ((1 << 10) - 1)) | ((Z[j + 2] & ((1 << 21) - 1)) << 10) | (Z[j + 3] << 31)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)(((((int)((uint)Z[j + 3] >> 1)) & ((1 << 20) - 1))) | (Z[j + 4] << 20)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 3), (int)((((int)((uint)Z[j + 4] >> 12)) & ((1 << 9) - 1)) | ((Z[j + 5] & ((1 << 21) - 1)) << 9) | (Z[j + 6] << 30)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 4), (int)(((((int)((uint)Z[j + 6] >> 2)) & ((1 << 19) - 1))) | (Z[j + 7] << 19)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 5), (int)((((int)((uint)Z[j + 7] >> 13)) & ((1 << 8) - 1)) | ((Z[j + 8] & ((1 << 21) - 1)) << 8) | (Z[j + 9] << 29)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 6), (int)(((((int)((uint)Z[j + 9] >> 3)) & ((1 << 18) - 1))) | (Z[j + 10] << 18)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 7), (int)((((int)((uint)Z[j + 10] >> 14)) & ((1 << 7) - 1)) | ((Z[j + 11] & ((1 << 21) - 1)) << 7) | (Z[j + 12] << 28)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 8), (int)(((((int)((uint)Z[j + 12] >> 4)) & ((1 << 17) - 1))) | (Z[j + 13] << 17)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 9), (int)((((int)((uint)Z[j + 13] >> 15)) & ((1 << 6) - 1)) | ((Z[j + 14] & ((1 << 21) - 1)) << 6) | (Z[j + 15] << 27)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 10), (int)(((((int)((uint)Z[j + 15] >> 5)) & ((1 << 16) - 1))) | (Z[j + 16] << 16)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 11), (int)((((int)((uint)Z[j + 16] >> 16)) & ((1 << 5) - 1)) | ((Z[j + 17] & ((1 << 21) - 1)) << 5) | (Z[j + 18] << 26)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 12), (int)(((((int)((uint)Z[j + 18] >> 6)) & ((1 << 15) - 1))) | (Z[j + 19] << 15)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 13), (int)((((int)((uint)Z[j + 19] >> 17)) & ((1 << 4) - 1)) | ((Z[j + 20] & ((1 << 21) - 1)) << 4) | (Z[j + 21] << 25)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 14), (int)(((((int)((uint)Z[j + 21] >> 7)) & ((1 << 14) - 1))) | (Z[j + 22] << 14)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 15), (int)((((int)((uint)Z[j + 22] >> 18)) & ((1 << 3) - 1)) | ((Z[j + 23] & ((1 << 21) - 1)) << 3) | (Z[j + 24] << 24)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 16), (int)(((((int)((uint)Z[j + 24] >> 8)) & ((1 << 13) - 1))) | (Z[j + 25] << 13)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 17), (int)((((int)((uint)Z[j + 25] >> 19)) & ((1 << 2) - 1)) | ((Z[j + 26] & ((1 << 21) - 1)) << 2) | (Z[j + 27] << 23)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 18), (int)(((((int)((uint)Z[j + 27] >> 9)) & ((1 << 12) - 1))) | (Z[j + 28] << 12)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 19), (int)((((int)((uint)Z[j + 28] >> 20)) & ((1 << 1) - 1)) | ((Z[j + 29] & ((1 << 21) - 1)) << 1) | (Z[j + 30] << 22)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 20), (int)(((((int)((uint)Z[j + 30] >> 10)) & ((1 << 11) - 1))) | (Z[j + 31] << 11)));

				j += (sizeof(int) * 8);

			}

			JavaSystem.arraycopy(C, cOffset, signature, signatureOffset + n * d / Byte.SIZE, Polynomial.HASH);

		}

		/// <summary>
		///***********************************************************************************************************************************************************************************************************
		/// Description:	Encode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************************************************************ </returns>
		public static void encodeSignatureIIISpeed(byte[] signature, int signatureOffset, byte[] C, int cOffset, int[] Z)
		{

			int j = 0;

			for (int i = 0; i < (Parameter.N_III_SPEED * Parameter.D_III_SPEED / (sizeof(int) * 8)); i += Parameter.D_III_SPEED / 2)
			{

				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 22) - 1))) | (Z[j + 1] << 22)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)(((((int)((uint)Z[j + 1] >> 10)) & ((1 << 12) - 1))) | (Z[j + 2] << 12)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)((((int)((uint)Z[j + 2] >> 20)) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 3), (int)(((((int)((uint)Z[j + 4] >> 8)) & ((1 << 14) - 1))) | (Z[j + 5] << 14)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 4), (int)((((int)((uint)Z[j + 5] >> 18)) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 5), (int)(((((int)((uint)Z[j + 7] >> 6)) & ((1 << 16) - 1))) | (Z[j + 8] << 16)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 6), (int)((((int)((uint)Z[j + 8] >> 16)) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 7), (int)(((((int)((uint)Z[j + 10] >> 4)) & ((1 << 18) - 1))) | (Z[j + 11] << 18)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 8), (int)((((int)((uint)Z[j + 11] >> 14)) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 9), (int)(((((int)((uint)Z[j + 13] >> 2)) & ((1 << 20) - 1))) | (Z[j + 14] << 20)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 10), (int)(((((int)((uint)Z[j + 14] >> 12)) & ((1 << 10) - 1))) | (Z[j + 15] << 10)));

				j += (sizeof(int) * 8) / 2;

			}

			JavaSystem.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE, Polynomial.HASH);

		}

		/// <summary>
		///***********************************************************************************************************************************************************************************************************
		/// Description:	Encode Signature for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************************************************************ </returns>
		public static void encodeSignatureIP(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
		{

			int j = 0;

			for (int i = 0; i < (Parameter.N_III_SPEED * Parameter.D_III_SPEED / (sizeof(int) * 8)); i += Parameter.D_III_SPEED / 2)
			{

				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 22) - 1))) | (Z[j + 1] << 22)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)(((((long)((ulong)Z[j + 1] >> 10)) & ((1 << 12) - 1))) | (Z[j + 2] << 12)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)((((long)((ulong)Z[j + 2] >> 20)) & ((1 << 2) - 1)) | ((Z[j + 3] & ((1 << 22) - 1)) << 2) | (Z[j + 4] << 24)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 3), (int)(((((long)((ulong)Z[j + 4] >> 8)) & ((1 << 14) - 1))) | (Z[j + 5] << 14)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 4), (int)((((long)((ulong)Z[j + 5] >> 18)) & ((1 << 4) - 1)) | ((Z[j + 6] & ((1 << 22) - 1)) << 4) | (Z[j + 7] << 26)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 5), (int)(((((long)((ulong)Z[j + 7] >> 6)) & ((1 << 16) - 1))) | (Z[j + 8] << 16)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 6), (int)((((long)((ulong)Z[j + 8] >> 16)) & ((1 << 6) - 1)) | ((Z[j + 9] & ((1 << 22) - 1)) << 6) | (Z[j + 10] << 28)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 7), (int)(((((long)((ulong)Z[j + 10] >> 4)) & ((1 << 18) - 1))) | (Z[j + 11] << 18)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 8), (int)((((long)((ulong)Z[j + 11] >> 14)) & ((1 << 8) - 1)) | ((Z[j + 12] & ((1 << 22) - 1)) << 8) | (Z[j + 13] << 30)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 9), (int)(((((long)((ulong)Z[j + 13] >> 2)) & ((1 << 20) - 1))) | (Z[j + 14] << 20)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 10), (int)(((((long)((ulong)Z[j + 14] >> 12)) & ((1 << 10) - 1))) | (Z[j + 15] << 10)));

				j += (sizeof(int) * 8) / 2;

			}

			JavaSystem.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE, Polynomial.HASH);

		}

		/// <summary>
		///*************************************************************************************************************************************************************
		/// Description:	Encode Signature for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="C"> </param>
		/// <param name="cOffset"> </param>
		/// <param name="Z">
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************************************** </returns>
		public static void encodeSignatureIIIP(byte[] signature, int signatureOffset, byte[] C, int cOffset, long[] Z)
		{

			int j = 0;

			for (int i = 0; i < (Parameter.N_III_P * Parameter.D_III_P / (sizeof(int) * 8)); i += Parameter.D_III_P / Byte.SIZE)
			{

				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 0), (int)(((Z[j + 0] & ((1 << 24) - 1))) | (Z[j + 1] << 24)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 1), (int)(((((long)((ulong)Z[j + 1] >> 8)) & ((1 << 16) - 1))) | (Z[j + 2] << 16)));
				CommonFunction.store32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (i + 2), (int)(((((long)((ulong)Z[j + 2] >> 16)) & ((1 << 8) - 1))) | (Z[j + 3] << 8)));

				j += Byte.SIZE / 2;

			}

			JavaSystem.arraycopy(C, cOffset, signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE, Polynomial.HASH);

		}

		/// <summary>
		///****************************************************************************************************************************
		/// Description:	Decode Signature for Heuristic qTESLA Security Category-1 and Category-3 (Option for Size)
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature </param>
		/// <param name="n">                    Polynomial Degree </param>
		/// <param name="d">                    Number of Rounded Bits
		/// </param>
		/// <returns> none
		/// ***************************************************************************************************************************** </returns>
		public static void decodeSignature(byte[] C, int[] Z, byte[] signature, int signatureOffset, int n, int d)
		{

			int j = 0;

			for (int i = 0; i < n; i += (sizeof(int) * 8))
			{

				Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) << 11) >> 11;

				Z[i + 1] = (((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 21)) | (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 22) >> 11);

				Z[i + 2] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 1) >> 11;

				Z[i + 3] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 31)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 12) >> 11);

				Z[i + 4] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 20)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 23) >> 11);

				Z[i + 5] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 2) >> 11;

				Z[i + 6] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) >> 30)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 13) >> 11);

				Z[i + 7] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) >> 19)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 24) >> 11);

				Z[i + 8] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 3) >> 11;

				Z[i + 9] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 29)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 14) >> 11);

				Z[i + 10] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) >> 18)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 25) >> 11);

				Z[i + 11] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 4) >> 11;

				Z[i + 12] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 28)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 15) >> 11);

				Z[i + 13] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) >> 17)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 26) >> 11);

				Z[i + 14] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 5) >> 11;

				Z[i + 15] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 27)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) << 16) >> 11);

				Z[i + 16] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 16)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 11)) << 27) >> 11);

				Z[i + 17] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 11)) << 6) >> 11;

				Z[i + 18] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 11)) >> 26)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 12)) << 17) >> 11);

				Z[i + 19] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 12)) >> 15)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 13)) << 28) >> 11);

				Z[i + 20] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 13)) << 7) >> 11;

				Z[i + 21] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 13)) >> 25)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 14)) << 18) >> 11);

				Z[i + 22] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 14)) >> 14)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 15)) << 29) >> 11);

				Z[i + 23] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 15)) << 8) >> 11;

				Z[i + 24] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 15)) >> 24)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 16)) << 19) >> 11);

				Z[i + 25] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 16)) >> 13)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 17)) << 30) >> 11);

				Z[i + 26] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 17)) << 9) >> 11;

				Z[i + 27] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 17)) >> 23)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 18)) << 20) >> 11);

				Z[i + 28] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 18)) >> 12)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 19)) << 31) >> 11);

				Z[i + 29] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 19)) << 10) >> 11;

				Z[i + 30] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 19)) >> 22)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 20)) << 21) >> 11);

				Z[i + 31] = CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 20)) >> 11;

				j += d;

			}

			JavaSystem.arraycopy(signature, signatureOffset + n * d / Byte.SIZE, C, 0, Polynomial.HASH);

		}

		/// <summary>
		///************************************************************************************************************************************
		/// Description:	Decode Signature for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns> none
		/// ************************************************************************************************************************************* </returns>
		public static void decodeSignatureIIISpeed(byte[] C, int[] Z, byte[] signature, int signatureOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_III_SPEED; i += (sizeof(int) * 8) / 2)
			{

				Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) << 10) >> 10;

				Z[i + 1] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 22)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 20) >> 10);

				Z[i + 2] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 12)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 30) >> 10);

				Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 8) >> 10;

				Z[i + 4] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 24)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 18) >> 10);

				Z[i + 5] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) >> 14)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 28) >> 10);

				Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 6) >> 10;

				Z[i + 7] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) >> 26)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 16) >> 10);

				Z[i + 8] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 16)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 26) >> 10);

				Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 4) >> 10;

				Z[i + 10] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) >> 28)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 14) >> 10);

				Z[i + 11] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 18)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 24) >> 10);

				Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 2) >> 10;

				Z[i + 13] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) >> 30)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 12) >> 10);

				Z[i + 14] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 20)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) << 22) >> 10);

				Z[i + 15] = CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 10;

				j += Parameter.D_III_SPEED / 2;

			}

			JavaSystem.arraycopy(signature, signatureOffset + Parameter.N_III_SPEED * Parameter.D_III_SPEED / Byte.SIZE, C, 0, Polynomial.HASH);

		}

		/// <summary>
		///**************************************************************************************************************************
		/// Description:	Decode Signature for Provably-Secure qTESLA Security Category-1
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns> none
		/// *************************************************************************************************************************** </returns>
		public static void decodeSignatureIP(byte[] C, long[] Z, byte[] signature, int signatureOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_I_P; i += (sizeof(int) * 8) / 2)
			{

				Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) << 10) >> 10;

				Z[i + 1] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 22)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 20) >> 10);

				Z[i + 2] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 12)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 30) >> 10);

				Z[i + 3] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 8) >> 10;

				Z[i + 4] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 24)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) << 18) >> 10);

				Z[i + 5] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 3)) >> 14)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 28) >> 10);

				Z[i + 6] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) << 6) >> 10;

				Z[i + 7] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 4)) >> 26)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) << 16) >> 10);

				Z[i + 8] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 5)) >> 16)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 26) >> 10);

				Z[i + 9] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) << 4) >> 10;

				Z[i + 10] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 6)) >> 28)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) << 14) >> 10);

				Z[i + 11] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 7)) >> 18)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 24) >> 10);

				Z[i + 12] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) << 2) >> 10;

				Z[i + 13] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 8)) >> 30)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) << 12) >> 10);

				Z[i + 14] = ((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 9)) >> 20)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) << 22) >> 10);

				Z[i + 15] = CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 10)) >> 10;

				j += Parameter.D_I_P / 2;

			}

			JavaSystem.arraycopy(signature, signatureOffset + Parameter.N_I_P * Parameter.D_I_P / Byte.SIZE, C, 0, Polynomial.HASH);

		}

		/// <summary>
		///**************************************************************************************************************************************
		/// Description:	Decode Signature for Provably-Secure qTESLA Security Category-3
		/// </summary>
		/// <param name="C"> </param>
		/// <param name="Z"> </param>
		/// <param name="signature">            Output Package Containing Signature </param>
		/// <param name="signatureOffset">        Starting Point of the Output Package Containing Signature
		/// </param>
		/// <returns> none
		/// *************************************************************************************************************************************** </returns>
		public static void decodeSignatureIIIP(byte[] C, long[] Z, byte[] signature, int signatureOffset)
		{

			int j = 0;

			for (int i = 0; i < Parameter.N_III_P; i += Byte.SIZE / 2)
			{

				Z[i + 0] = (CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) << 8) >> 8;

				Z[i + 1] = (((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 0)) >> 24)) & ((1 << 8) - 1)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) << 16) >> 8);

				Z[i + 2] = (((int)((uint)CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 1)) >> 16)) & ((1 << 16) - 1)) | ((CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) << 24) >> 8);

				Z[i + 3] = CommonFunction.load32(signature, signatureOffset + (sizeof(int) * 8) / Byte.SIZE * (j + 2)) >> 8;

				j += Byte.SIZE / 2 - 1;

			}

			JavaSystem.arraycopy(signature, signatureOffset + Parameter.N_III_P * Parameter.D_III_P / Byte.SIZE, C, 0, Polynomial.HASH);

		}

	}
}