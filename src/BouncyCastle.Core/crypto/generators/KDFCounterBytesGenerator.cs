using System;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.generators
{

	using KDFCounterParameters = org.bouncycastle.crypto.@params.KDFCounterParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	/// <summary>
	/// This KDF has been defined by the publicly available NIST SP 800-108 specification.
	/// NIST SP800-108 allows for alternative orderings of the input fields, meaning that the input can be formated in multiple ways.
	/// There are 3 supported formats:  - Below [i]_2 is a counter of r-bits length concatenated to the fixedInputData.
	/// <ul>
	/// <li>1: K(i) := PRF( KI, [i]_2 || Label || 0x00 || Context || [L]_2 ) with the counter at the very beginning of the fixedInputData (The default implementation has this format)</li>
	/// <li>2: K(i) := PRF( KI, Label || 0x00 || Context || [L]_2 || [i]_2 ) with the counter at the very end of the fixedInputData</li>
	/// <li>3a: K(i) := PRF( KI, Label || 0x00 || [i]_2 || Context || [L]_2 ) OR:</li>
	/// <li>3b: K(i) := PRF( KI, Label || 0x00 || [i]_2 || [L]_2 || Context ) OR:</li>
	/// <li>3c: K(i) := PRF( KI, Label || [i]_2 || 0x00 || Context || [L]_2 ) etc... with the counter somewhere in the 'middle' of the fixedInputData.</li>
	/// </ul>
	/// This function must be called with the following KDFCounterParameters():
	/// <ul>
	///  <li>KI</li>
	///  <li>The part of the fixedInputData that comes BEFORE the counter OR null</li>
	///  <li>the part of the fixedInputData that comes AFTER the counter OR null </li>
	///  <li>the length of the counter in bits (not bytes)</li>
	/// </ul>
	/// Resulting function calls assuming an 8 bit counter.
	/// <ul>
	/// <li>1.  KDFCounterParameters(ki, 	null, 									"Label || 0x00 || Context || [L]_2]",	8);</li>
	/// <li>2.  KDFCounterParameters(ki, 	"Label || 0x00 || Context || [L]_2]", 	null,									8);</li>
	/// <li>3a. KDFCounterParameters(ki, 	"Label || 0x00",						"Context || [L]_2]",					8);</li>
	/// <li>3b. KDFCounterParameters(ki, 	"Label || 0x00",						"[L]_2] || Context",					8);</li>
	/// <li>3c. KDFCounterParameters(ki, 	"Label", 								"0x00 || Context || [L]_2]",			8);</li>
	/// </ul>
	/// </summary>
	public class KDFCounterBytesGenerator : MacDerivationFunction
	{

		private static readonly BigInteger INTEGER_MAX = BigInteger.valueOf(int.MaxValue);
		private static readonly BigInteger TWO = BigInteger.valueOf(2);

		// please refer to the standard for the meaning of the variable names
		// all field lengths are in bytes, not in bits as specified by the standard

		// fields set by the constructor
		private readonly Mac prf;
		private readonly int h;

		// fields set by init
		private byte[] fixedInputDataCtrPrefix;
		private byte[] fixedInputData_afterCtr;
		private int maxSizeExcl;
		// ios is i defined as an octet string (the binary representation)
		private byte[] ios;

		// operational
		private int generatedBytes;
		// k is used as buffer for all K(i) values
		private byte[] k;


		public KDFCounterBytesGenerator(Mac prf)
		{
			this.prf = prf;
			this.h = prf.getMacSize();
			this.k = new byte[h];
		}


		public virtual void init(DerivationParameters param)
		{
			if (!(param is KDFCounterParameters))
			{
				throw new IllegalArgumentException("Wrong type of arguments given");
			}

			KDFCounterParameters kdfParams = (KDFCounterParameters)param;

			// --- init mac based PRF ---

			this.prf.init(new KeyParameter(kdfParams.getKI()));

			// --- set arguments ---

			this.fixedInputDataCtrPrefix = kdfParams.getFixedInputDataCounterPrefix();
			this.fixedInputData_afterCtr = kdfParams.getFixedInputDataCounterSuffix();

			int r = kdfParams.getR();
			this.ios = new byte[r / 8];

			BigInteger maxSize = TWO.pow(r).multiply(BigInteger.valueOf(h));
			this.maxSizeExcl = maxSize.compareTo(INTEGER_MAX) == 1 ? int.MaxValue : maxSize.intValue();

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


			// special case for K(0): K(0) is empty, so no update
			prf.update(fixedInputDataCtrPrefix, 0, fixedInputDataCtrPrefix.Length);
			prf.update(ios, 0, ios.Length);
			prf.update(fixedInputData_afterCtr, 0, fixedInputData_afterCtr.Length);
			prf.doFinal(k, 0);
		}
	}

}