using org.bouncycastle.crypto.macs;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{
							
	public class GOST28147WrapEngine : Wrapper
	{
		private GOST28147Engine cipher = new GOST28147Engine();
		private GOST28147Mac mac = new GOST28147Mac();

		public virtual void init(bool forWrapping, CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				ParametersWithRandom pr = (ParametersWithRandom)param;
				param = pr.getParameters();
			}

			ParametersWithUKM pU = (ParametersWithUKM)param;

			cipher.init(forWrapping, pU.getParameters());

			KeyParameter kParam;

			if (pU.getParameters() is ParametersWithSBox)
			{
				kParam = (KeyParameter)((ParametersWithSBox)pU.getParameters()).getParameters();
			}
			else
			{
				kParam = (KeyParameter)pU.getParameters();
			}


			mac.init(new ParametersWithIV(kParam, pU.getUKM()));
		}

		public virtual string getAlgorithmName()
		{
			return "GOST28147Wrap";
		}

		public virtual byte[] wrap(byte[] input, int inOff, int inLen)
		{
			mac.update(input, inOff, inLen);

			byte[] wrappedKey = new byte[inLen + mac.getMacSize()];

			cipher.processBlock(input, inOff, wrappedKey, 0);
			cipher.processBlock(input, inOff + 8, wrappedKey, 8);
			cipher.processBlock(input, inOff + 16, wrappedKey, 16);
			cipher.processBlock(input, inOff + 24, wrappedKey, 24);

			mac.doFinal(wrappedKey, inLen);

			return wrappedKey;
		}

		public virtual byte[] unwrap(byte[] input, int inOff, int inLen)
		{
			byte[] decKey = new byte[inLen - mac.getMacSize()];

			cipher.processBlock(input, inOff, decKey, 0);
			cipher.processBlock(input, inOff + 8, decKey, 8);
			cipher.processBlock(input, inOff + 16, decKey, 16);
			cipher.processBlock(input, inOff + 24, decKey, 24);

			byte[] macResult = new byte[mac.getMacSize()];

			mac.update(decKey, 0, decKey.Length);

			mac.doFinal(macResult, 0);

			byte[] macExpected = new byte[mac.getMacSize()];

			JavaSystem.arraycopy(input, inOff + inLen - 4, macExpected, 0, mac.getMacSize());

			if (!Arrays.constantTimeAreEqual(macResult, macExpected))
			{
				throw new IllegalStateException("mac mismatch");
			}

			return decKey;
		}
	}

}