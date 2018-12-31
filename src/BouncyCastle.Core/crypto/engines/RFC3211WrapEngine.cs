using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.modes;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{

				
	/// <summary>
	/// an implementation of the RFC 3211 Key Wrap
	/// Specification.
	/// </summary>
	public class RFC3211WrapEngine : Wrapper
	{
		private CBCBlockCipher engine;
		private ParametersWithIV param;
		private bool forWrapping;
		private SecureRandom rand;

		public RFC3211WrapEngine(BlockCipher engine)
		{
			this.engine = new CBCBlockCipher(engine);
		}

		public virtual void init(bool forWrapping, CipherParameters param)
		{
			this.forWrapping = forWrapping;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom p = (ParametersWithRandom)param;

				rand = p.getRandom();

				if (!(p.getParameters() is ParametersWithIV))
				{
					throw new IllegalArgumentException("RFC3211Wrap requires an IV");
				}

				this.param = (ParametersWithIV)p.getParameters();
			}
			else
			{
				if (forWrapping)
				{
					rand = CryptoServicesRegistrar.getSecureRandom();
				}

				if (!(param is ParametersWithIV))
				{
					throw new IllegalArgumentException("RFC3211Wrap requires an IV");
				}

				this.param = (ParametersWithIV)param;
			}
		}

		public virtual string getAlgorithmName()
		{
			return engine.getUnderlyingCipher().getAlgorithmName() + "/RFC3211Wrap";
		}

		public virtual byte[] wrap(byte[] @in, int inOff, int inLen)
		{
			if (!forWrapping)
			{
				throw new IllegalStateException("not set for wrapping");
			}

			if (inLen > 255 || inLen < 0)
			{
				throw new IllegalArgumentException("input must be from 0 to 255 bytes");
			}

			engine.init(true, param);

			int blockSize = engine.getBlockSize();
			byte[] cekBlock;

			if (inLen + 4 < blockSize * 2)
			{
				cekBlock = new byte[blockSize * 2];
			}
			else
			{
				cekBlock = new byte[(inLen + 4) % blockSize == 0 ? inLen + 4 : ((inLen + 4) / blockSize + 1) * blockSize];
			}

			cekBlock[0] = (byte)inLen;

			JavaSystem.arraycopy(@in, inOff, cekBlock, 4, inLen);

			byte[] pad = new byte[cekBlock.Length - (inLen + 4)];

			rand.nextBytes(pad);
			JavaSystem.arraycopy(pad, 0, cekBlock, inLen + 4, pad.Length);

			cekBlock[1] = (byte)~cekBlock[4];
			cekBlock[2] = (byte)~cekBlock[4 + 1];
			cekBlock[3] = (byte)~cekBlock[4 + 2];

			for (int i = 0; i < cekBlock.Length; i += blockSize)
			{
				engine.processBlock(cekBlock, i, cekBlock, i);
			}

			for (int i = 0; i < cekBlock.Length; i += blockSize)
			{
				engine.processBlock(cekBlock, i, cekBlock, i);
			}

			return cekBlock;
		}

		public virtual byte[] unwrap(byte[] @in, int inOff, int inLen)
		{
			if (forWrapping)
			{
				throw new IllegalStateException("not set for unwrapping");
			}

			int blockSize = engine.getBlockSize();

			if (inLen < 2 * blockSize)
			{
				throw new InvalidCipherTextException("input too short");
			}

			byte[] cekBlock = new byte[inLen];
			byte[] iv = new byte[blockSize];

			JavaSystem.arraycopy(@in, inOff, cekBlock, 0, inLen);
			JavaSystem.arraycopy(@in, inOff, iv, 0, iv.Length);

			engine.init(false, new ParametersWithIV(param.getParameters(), iv));

			for (int i = blockSize; i < cekBlock.Length; i += blockSize)
			{
				engine.processBlock(cekBlock, i, cekBlock, i);
			}

			JavaSystem.arraycopy(cekBlock, cekBlock.Length - iv.Length, iv, 0, iv.Length);

			engine.init(false, new ParametersWithIV(param.getParameters(), iv));

			engine.processBlock(cekBlock, 0, cekBlock, 0);

			engine.init(false, param);

			for (int i = 0; i < cekBlock.Length; i += blockSize)
			{
				engine.processBlock(cekBlock, i, cekBlock, i);
			}

			bool invalidLength = ((cekBlock[0] & 0xff) > cekBlock.Length - 4);

			byte[] key;
			if (invalidLength)
			{
				key = new byte[cekBlock.Length - 4];
			}
			else
			{
				key = new byte[cekBlock[0] & 0xff];
			}

			JavaSystem.arraycopy(cekBlock, 4, key, 0, key.Length);

			// Note: Using constant time comparison
			int nonEqual = 0;
			for (int i = 0; i != 3; i++)
			{
				byte check = (byte)~cekBlock[1 + i];
				nonEqual |= (check ^ cekBlock[4 + i]);
			}

			Arrays.clear(cekBlock);

			if (nonEqual != 0 | invalidLength)
			{
				throw new InvalidCipherTextException("wrapped key corrupted");
			}

			return key;
		}
	}

}