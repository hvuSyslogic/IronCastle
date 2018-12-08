﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.engines
{

	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// implementation of GOST 28147-89
	/// </summary>
	public class GOST28147Engine : BlockCipher
	{
		protected internal const int BLOCK_SIZE = 8;
		private int[] workingKey = null;
		private bool forEncryption;

		private byte[] S = Sbox_Default;

		// these are the S-boxes given in Applied Cryptography 2nd Ed., p. 333
		// This is default S-box!
		private static byte[] Sbox_Default = new byte[] {0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3, 0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9, 0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB, 0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3, 0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2, 0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE, 0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC, 0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC};

		/*
		 * class content S-box parameters for encrypting
		 * getting from, see: http://tools.ietf.org/id/draft-popov-cryptopro-cpalgs-01.txt
		 *                    http://tools.ietf.org/id/draft-popov-cryptopro-cpalgs-02.txt
		 */
		private static byte[] ESbox_Test = new byte[] {0x4, 0x2, 0xF, 0x5, 0x9, 0x1, 0x0, 0x8, 0xE, 0x3, 0xB, 0xC, 0xD, 0x7, 0xA, 0x6, 0xC, 0x9, 0xF, 0xE, 0x8, 0x1, 0x3, 0xA, 0x2, 0x7, 0x4, 0xD, 0x6, 0x0, 0xB, 0x5, 0xD, 0x8, 0xE, 0xC, 0x7, 0x3, 0x9, 0xA, 0x1, 0x5, 0x2, 0x4, 0x6, 0xF, 0x0, 0xB, 0xE, 0x9, 0xB, 0x2, 0x5, 0xF, 0x7, 0x1, 0x0, 0xD, 0xC, 0x6, 0xA, 0x4, 0x3, 0x8, 0x3, 0xE, 0x5, 0x9, 0x6, 0x8, 0x0, 0xD, 0xA, 0xB, 0x7, 0xC, 0x2, 0x1, 0xF, 0x4, 0x8, 0xF, 0x6, 0xB, 0x1, 0x9, 0xC, 0x5, 0xD, 0x3, 0x7, 0xA, 0x0, 0xE, 0x2, 0x4, 0x9, 0xB, 0xC, 0x0, 0x3, 0x6, 0x7, 0x5, 0x4, 0x8, 0xE, 0xF, 0x1, 0xA, 0x2, 0xD, 0xC, 0x6, 0x5, 0x2, 0xB, 0x0, 0x9, 0xD, 0x3, 0xE, 0x7, 0xA, 0xF, 0x4, 0x1, 0x8};

		private static byte[] ESbox_A = new byte[] {0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5, 0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1, 0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9, 0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6, 0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6, 0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6, 0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE, 0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4};

		private static byte[] ESbox_B = new byte[] {0x8, 0x4, 0xB, 0x1, 0x3, 0x5, 0x0, 0x9, 0x2, 0xE, 0xA, 0xC, 0xD, 0x6, 0x7, 0xF, 0x0, 0x1, 0x2, 0xA, 0x4, 0xD, 0x5, 0xC, 0x9, 0x7, 0x3, 0xF, 0xB, 0x8, 0x6, 0xE, 0xE, 0xC, 0x0, 0xA, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x8, 0xF, 0x3, 0x6, 0x1, 0x4, 0x7, 0x5, 0x0, 0xD, 0xB, 0x6, 0x1, 0x2, 0x3, 0xA, 0xC, 0xF, 0x4, 0xE, 0x9, 0x8, 0x2, 0x7, 0xC, 0xF, 0x9, 0x5, 0xA, 0xB, 0x1, 0x4, 0x0, 0xD, 0x6, 0x8, 0xE, 0x3, 0x8, 0x3, 0x2, 0x6, 0x4, 0xD, 0xE, 0xB, 0xC, 0x1, 0x7, 0xF, 0xA, 0x0, 0x9, 0x5, 0x5, 0x2, 0xA, 0xB, 0x9, 0x1, 0xC, 0x3, 0x7, 0x4, 0xD, 0x0, 0x6, 0xF, 0x8, 0xE, 0x0, 0x4, 0xB, 0xE, 0x8, 0x3, 0x7, 0x1, 0xA, 0x2, 0x9, 0x6, 0xF, 0xD, 0x5, 0xC};

		private static byte[] ESbox_C = new byte[] {0x1, 0xB, 0xC, 0x2, 0x9, 0xD, 0x0, 0xF, 0x4, 0x5, 0x8, 0xE, 0xA, 0x7, 0x6, 0x3, 0x0, 0x1, 0x7, 0xD, 0xB, 0x4, 0x5, 0x2, 0x8, 0xE, 0xF, 0xC, 0x9, 0xA, 0x6, 0x3, 0x8, 0x2, 0x5, 0x0, 0x4, 0x9, 0xF, 0xA, 0x3, 0x7, 0xC, 0xD, 0x6, 0xE, 0x1, 0xB, 0x3, 0x6, 0x0, 0x1, 0x5, 0xD, 0xA, 0x8, 0xB, 0x2, 0x9, 0x7, 0xE, 0xF, 0xC, 0x4, 0x8, 0xD, 0xB, 0x0, 0x4, 0x5, 0x1, 0x2, 0x9, 0x3, 0xC, 0xE, 0x6, 0xF, 0xA, 0x7, 0xC, 0x9, 0xB, 0x1, 0x8, 0xE, 0x2, 0x4, 0x7, 0x3, 0x6, 0x5, 0xA, 0x0, 0xF, 0xD, 0xA, 0x9, 0x6, 0x8, 0xD, 0xE, 0x2, 0x0, 0xF, 0x3, 0x5, 0xB, 0x4, 0x1, 0xC, 0x7, 0x7, 0x4, 0x0, 0x5, 0xA, 0x2, 0xF, 0xE, 0xC, 0x6, 0x1, 0xB, 0xD, 0x9, 0x3, 0x8};

		private static byte[] ESbox_D = new byte[] {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3, 0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1, 0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2, 0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8, 0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1, 0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6, 0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7, 0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE};

		// Rosstandart param-Z
		private static byte[] Param_Z = new byte[] {0xc, 0x4, 0x6, 0x2, 0xa, 0x5, 0xb, 0x9, 0xe, 0x8, 0xd, 0x7, 0x0, 0x3, 0xf, 0x1, 0x6, 0x8, 0x2, 0x3, 0x9, 0xa, 0x5, 0xc, 0x1, 0xe, 0x4, 0x7, 0xb, 0xd, 0x0, 0xf, 0xb, 0x3, 0x5, 0x8, 0x2, 0xf, 0xa, 0xd, 0xe, 0x1, 0x7, 0x4, 0xc, 0x9, 0x6, 0x0, 0xc, 0x8, 0x2, 0x1, 0xd, 0x4, 0xf, 0x6, 0x7, 0x0, 0xa, 0x5, 0x3, 0xe, 0x9, 0xb, 0x7, 0xf, 0x5, 0xa, 0x8, 0x1, 0x6, 0xd, 0x0, 0x9, 0x3, 0xe, 0xb, 0x4, 0x2, 0xc, 0x5, 0xd, 0xf, 0x6, 0x9, 0x2, 0xc, 0xa, 0xb, 0x7, 0x8, 0x1, 0x4, 0x3, 0xe, 0x0, 0x8, 0xe, 0x2, 0x5, 0x6, 0x9, 0x1, 0xc, 0xf, 0x4, 0xb, 0x0, 0xd, 0xa, 0x3, 0x7, 0x1, 0x7, 0xe, 0xd, 0x0, 0x5, 0x8, 0x3, 0x4, 0xf, 0xa, 0x6, 0x9, 0xc, 0xb, 0x2};

		//S-box for digest
		private static byte[] DSbox_Test = new byte[] {0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3, 0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9, 0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB, 0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3, 0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2, 0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE, 0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC, 0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC};

		private static byte[] DSbox_A = new byte[] {0xA, 0x4, 0x5, 0x6, 0x8, 0x1, 0x3, 0x7, 0xD, 0xC, 0xE, 0x0, 0x9, 0x2, 0xB, 0xF, 0x5, 0xF, 0x4, 0x0, 0x2, 0xD, 0xB, 0x9, 0x1, 0x7, 0x6, 0x3, 0xC, 0xE, 0xA, 0x8, 0x7, 0xF, 0xC, 0xE, 0x9, 0x4, 0x1, 0x0, 0x3, 0xB, 0x5, 0x2, 0x6, 0xA, 0x8, 0xD, 0x4, 0xA, 0x7, 0xC, 0x0, 0xF, 0x2, 0x8, 0xE, 0x1, 0x6, 0x5, 0xD, 0xB, 0x9, 0x3, 0x7, 0x6, 0x4, 0xB, 0x9, 0xC, 0x2, 0xA, 0x1, 0x8, 0x0, 0xE, 0xF, 0xD, 0x3, 0x5, 0x7, 0x6, 0x2, 0x4, 0xD, 0x9, 0xF, 0x0, 0xA, 0x1, 0x5, 0xB, 0x8, 0xE, 0xC, 0x3, 0xD, 0xE, 0x4, 0x1, 0x7, 0x0, 0x5, 0xA, 0x3, 0xC, 0x8, 0xF, 0x6, 0x2, 0x9, 0xB, 0x1, 0x3, 0xA, 0x9, 0x5, 0xB, 0x4, 0xF, 0x8, 0x6, 0x7, 0xE, 0xD, 0x0, 0x2, 0xC};

		//
		// pre-defined sbox table
		//
		private static Hashtable sBoxes = new Hashtable();

		static GOST28147Engine()
		{
			addSBox("Default", Sbox_Default);
			addSBox("E-TEST", ESbox_Test);
			addSBox("E-A", ESbox_A);
			addSBox("E-B", ESbox_B);
			addSBox("E-C", ESbox_C);
			addSBox("E-D", ESbox_D);
			addSBox("Param-Z", Param_Z);
			addSBox("D-TEST", DSbox_Test);
			addSBox("D-A", DSbox_A);
		}

		private static void addSBox(string sBoxName, byte[] sBox)
		{
			sBoxes.put(Strings.toUpperCase(sBoxName), sBox);
		}

		/// <summary>
		/// standard constructor.
		/// </summary>
		public GOST28147Engine()
		{
		}

		/// <summary>
		/// initialise an GOST28147 cipher.
		/// </summary>
		/// <param name="forEncryption"> whether or not we are for encryption. </param>
		/// <param name="params"> the parameters required to set up the cipher. </param>
		/// <exception cref="IllegalArgumentException"> if the params argument is
		/// inappropriate. </exception>
		public virtual void init(bool forEncryption, CipherParameters @params)
		{
			if (@params is ParametersWithSBox)
			{
				ParametersWithSBox param = (ParametersWithSBox)@params;

				//
				// Set the S-Box
				//
				byte[] sBox = param.getSBox();
				if (sBox.Length != Sbox_Default.Length)
				{
					throw new IllegalArgumentException("invalid S-box passed to GOST28147 init");
				}
				this.S = Arrays.clone(sBox);

				//
				// set key if there is one
				//
				if (param.getParameters() != null)
				{
					workingKey = generateWorkingKey(forEncryption, ((KeyParameter)param.getParameters()).getKey());
				}
			}
			else if (@params is KeyParameter)
			{
				workingKey = generateWorkingKey(forEncryption, ((KeyParameter)@params).getKey());
			}
			else if (@params != null)
			{
			   throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + @params.GetType().getName());
			}
		}

		public virtual string getAlgorithmName()
		{
			return "GOST28147";
		}

		public virtual int getBlockSize()
		{
			return BLOCK_SIZE;
		}

		public virtual int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			if (workingKey == null)
			{
				throw new IllegalStateException("GOST28147 engine not initialised");
			}

			if ((inOff + BLOCK_SIZE) > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			if ((outOff + BLOCK_SIZE) > @out.Length)
			{
				throw new OutputLengthException("output buffer too short");
			}

			GOST28147Func(workingKey, @in, inOff, @out, outOff);

			return BLOCK_SIZE;
		}

		public virtual void reset()
		{
		}

		private int[] generateWorkingKey(bool forEncryption, byte[] userKey)
		{
			 this.forEncryption = forEncryption;

			if (userKey.Length != 32)
			{
				throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
			}

			int[] key = new int[8];
			for (int i = 0; i != 8; i++)
			{
				key[i] = bytesToint(userKey,i * 4);
			}

			return key;
		}

		private int GOST28147_mainStep(int n1, int key)
		{
			int cm = (key + n1); // CM1

			// S-box replacing

			int om = S[0 + ((cm >> (0 * 4)) & 0xF)] << (0 * 4);
			   om += S[16 + ((cm >> (1 * 4)) & 0xF)] << (1 * 4);
			   om += S[32 + ((cm >> (2 * 4)) & 0xF)] << (2 * 4);
			   om += S[48 + ((cm >> (3 * 4)) & 0xF)] << (3 * 4);
			   om += S[64 + ((cm >> (4 * 4)) & 0xF)] << (4 * 4);
			   om += S[80 + ((cm >> (5 * 4)) & 0xF)] << (5 * 4);
			   om += S[96 + ((cm >> (6 * 4)) & 0xF)] << (6 * 4);
			   om += S[112 + ((cm >> (7 * 4)) & 0xF)] << (7 * 4);

			return om << 11 | (int)((uint)om >> (32 - 11)); // 11-leftshift
		}

		private void GOST28147Func(int[] workingKey, byte[] @in, int inOff, byte[] @out, int outOff)
		{
			int N1, N2, tmp; //tmp -> for saving N1
			N1 = bytesToint(@in, inOff);
			N2 = bytesToint(@in, inOff + 4);

			if (this.forEncryption)
			{
			  for (int k = 0; k < 3; k++) // 1-24 steps
			  {
				for (int j = 0; j < 8; j++)
				{
					tmp = N1;
					N1 = N2 ^ GOST28147_mainStep(N1, workingKey[j]); // CM2
					N2 = tmp;
				}
			  }
			  for (int j = 7; j > 0; j--) // 25-31 steps
			  {
				  tmp = N1;
				  N1 = N2 ^ GOST28147_mainStep(N1, workingKey[j]); // CM2
				  N2 = tmp;
			  }
			}
			else //decrypt
			{
			  for (int j = 0; j < 8; j++) // 1-8 steps
			  {
				 tmp = N1;
				 N1 = N2 ^ GOST28147_mainStep(N1, workingKey[j]); // CM2
				 N2 = tmp;
			  }
			  for (int k = 0; k < 3; k++) //9-31 steps
			  {
				for (int j = 7; j >= 0; j--)
				{
					if ((k == 2) && (j == 0))
					{
						break; // break 32 step
					}
					tmp = N1;
					N1 = N2 ^ GOST28147_mainStep(N1, workingKey[j]); // CM2
					N2 = tmp;
				}
			  }
			}

			N2 = N2 ^ GOST28147_mainStep(N1, workingKey[0]); // 32 step (N1=N1)

			intTobytes(N1, @out, outOff);
			intTobytes(N2, @out, outOff + 4);
		}

		//array of bytes to type int
		private int bytesToint(byte[] @in, int inOff)
		{
			return ((@in[inOff + 3] << 24) & unchecked((int)0xff000000)) + ((@in[inOff + 2] << 16) & 0xff0000) + ((@in[inOff + 1] << 8) & 0xff00) + (@in[inOff] & 0xff);
		}

		//int to array of bytes
		private void intTobytes(int num, byte[] @out, int outOff)
		{
				@out[outOff + 3] = (byte)((int)((uint)num >> 24));
				@out[outOff + 2] = (byte)((int)((uint)num >> 16));
				@out[outOff + 1] = (byte)((int)((uint)num >> 8));
				@out[outOff] = (byte)num;
		}

		/// <summary>
		/// Return the S-Box associated with SBoxName </summary>
		/// <param name="sBoxName"> name of the S-Box </param>
		/// <returns> byte array representing the S-Box </returns>
		public static byte[] getSBox(string sBoxName)
		{
			byte[] sBox = (byte[])sBoxes.get(Strings.toUpperCase(sBoxName));

			if (sBox == null)
			{
				throw new IllegalArgumentException("Unknown S-Box - possible types: " + @"""Default"", ""E-Test"", ""E-A"", ""E-B"", ""E-C"", ""E-D"", ""Param-Z"", ""D-Test"", ""D-A"".");
			}

			return Arrays.clone(sBox);
		}

		public static string getSBoxName(byte[] sBox)
		{
			for (Enumeration en = sBoxes.keys(); en.hasMoreElements();)
			{
				string name = (string)en.nextElement();
				byte[] sb = (byte[])sBoxes.get(name);
				if (Arrays.areEqual(sb, sBox))
				{
					return name;
				}
			}

			throw new IllegalArgumentException("SBOX provided did not map to a known one");
		}
	}

}