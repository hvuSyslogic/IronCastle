using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{

		
	/// <summary>
	/// This KDF has been defined by the publicly available NIST SP 800-108 specification.
	/// </summary>
	public class KDFFeedbackBytesGenerator : MacDerivationFunction
	{

		private static readonly BigInteger INTEGER_MAX = BigInteger.valueOf(int.MaxValue);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		// please refer to the standard for the meaning of the variable names
		// all field lengths are in bytes, not in bits as specified by the standard

		// fields set by the constructor
		private readonly Mac prf;
		private readonly int h;

		// fields set by init
		private byte[] fixedInputData;
		private int maxSizeExcl;
		// ios is i defined as an octet string (the binary representation)
		private byte[] ios;
		private byte[] iv;
		private bool useCounter;

		// operational
		private int generatedBytes;
		// k is used as buffer for all K(i) values
		private byte[] k;


		public KDFFeedbackBytesGenerator(Mac prf)
		{
			this.prf = prf;
			this.h = prf.getMacSize();
			this.k = new byte[h];
		}

		public virtual void init(DerivationParameters @params)
		{
			if (!(@params is KDFFeedbackParameters))
			{
				throw new IllegalArgumentException("Wrong type of arguments given");
			}

			KDFFeedbackParameters feedbackParams = (KDFFeedbackParameters)@params;

			// --- init mac based PRF ---

			this.prf.init(new KeyParameter(feedbackParams.getKI()));

			// --- set arguments ---

			this.fixedInputData = feedbackParams.getFixedInputData();

			int r = feedbackParams.getR();
			this.ios = new byte[r / 8];

			if (feedbackParams.useCounter())
			{
				// this is more conservative than the spec
				BigInteger maxSize = TWO.pow(r).multiply(BigInteger.valueOf(h));
				this.maxSizeExcl = maxSize.compareTo(INTEGER_MAX) == 1 ? int.MaxValue : maxSize.intValue();
			}
			else
			{
				this.maxSizeExcl = int.MaxValue;
			}

			this.iv = feedbackParams.getIV();
			this.useCounter = feedbackParams.useCounter();

			// --- set operational state ---

			generatedBytes = 0;
		}

		public virtual Mac getMac()
		{
			return prf;
		}

		public virtual int generateBytes(byte[] @out, int outOff, int len)
		{

			int generatedBytesAfter = generatedBytes + len;
			if (generatedBytesAfter < 0 || generatedBytesAfter >= maxSizeExcl)
			{
				throw new DataLengthException("Current KDFCTR may only be used for " + maxSizeExcl + " bytes");
			}

			if (generatedBytes % h == 0)
			{
				generateNext();
			}

			// copy what is left in the currentT (1..hash
			int toGenerate = len;
			int posInK = generatedBytes % h;
			int leftInK = h - generatedBytes % h;
			int toCopy = Math.Min(leftInK, toGenerate);
			JavaSystem.arraycopy(k, posInK, @out, outOff, toCopy);
			generatedBytes += toCopy;
			toGenerate -= toCopy;
			outOff += toCopy;

			while (toGenerate > 0)
			{
				generateNext();
				toCopy = Math.Min(h, toGenerate);
				JavaSystem.arraycopy(k, 0, @out, outOff, toCopy);
				generatedBytes += toCopy;
				toGenerate -= toCopy;
				outOff += toCopy;
			}

			return len;
		}

		private void generateNext()
		{

			// TODO enable IV
			if (generatedBytes == 0)
			{
				prf.update(iv, 0, iv.Length);
			}
			else
			{
				prf.update(k, 0, k.Length);
			}

			if (useCounter)
			{
				int i = generatedBytes / h + 1;

				// encode i into counter buffer
				switch (ios.Length)
				{
				case 4:
					ios[0] = (byte)((int)((uint)i >> 24));
					// fall through
					goto case 3;
				case 3:
					ios[ios.Length - 3] = (byte)((int)((uint)i >> 16));
					// fall through
					goto case 2;
				case 2:
					ios[ios.Length - 2] = (byte)((int)((uint)i >> 8));
					// fall through
					goto case 1;
				case 1:
					ios[ios.Length - 1] = (byte)i;
					break;
				default:
					throw new IllegalStateException("Unsupported size of counter i");
				}
				prf.update(ios, 0, ios.Length);
			}

			prf.update(fixedInputData, 0, fixedInputData.Length);
			prf.doFinal(k, 0);
		}
	}

}