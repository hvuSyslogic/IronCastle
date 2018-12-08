﻿namespace org.bouncycastle.crypto.modes
{
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;
	using ParametersWithSBox = org.bouncycastle.crypto.@params.ParametersWithSBox;

	/// <summary>
	/// An implementation of the GOST CFB mode with CryptoPro key meshing as described in RFC 4357.
	/// </summary>
	public class GCFBBlockCipher : StreamBlockCipher
	{
		private static readonly byte[] C = new byte[] {0x69, 0x00, 0x72, 0x22, 0x64, unchecked((byte)0xC9), 0x04, 0x23, unchecked((byte)0x8D), 0x3A, unchecked((byte)0xDB), unchecked((byte)0x96), 0x46, unchecked((byte)0xE9), 0x2A, unchecked((byte)0xC4), 0x18, unchecked((byte)0xFE), unchecked((byte)0xAC), unchecked((byte)0x94), 0x00, unchecked((byte)0xED), 0x07, 0x12, unchecked((byte)0xC0), unchecked((byte)0x86), unchecked((byte)0xDC), unchecked((byte)0xC2), unchecked((byte)0xEF), 0x4C, unchecked((byte)0xA9), 0x2B};

		private readonly CFBBlockCipher cfbEngine;

		private KeyParameter key;
		private long counter = 0;
		private bool forEncryption;

		public GCFBBlockCipher(BlockCipher engine) : base(engine)
		{

			this.cfbEngine = new CFBBlockCipher(engine, engine.getBlockSize() * 8);
		}

		public override void init(bool forEncryption, CipherParameters @params)
		{
			counter = 0;
			cfbEngine.init(forEncryption, @params);

			this.forEncryption = forEncryption;

			if (@params is ParametersWithIV)
			{
				@params = ((ParametersWithIV)@params).getParameters();
			}

			if (@params is ParametersWithRandom)
			{
				@params = ((ParametersWithRandom)@params).getParameters();
			}

			if (@params is ParametersWithSBox)
			{
				@params = ((ParametersWithSBox)@params).getParameters();
			}

			key = (KeyParameter)@params;
		}

		public override string getAlgorithmName()
		{
			string name = cfbEngine.getAlgorithmName();
			return name.Substring(0, name.IndexOf('/')) + "/G" + name.Substring(name.IndexOf('/') + 1);
		}

		public override int getBlockSize()
		{
			return cfbEngine.getBlockSize();
		}

		public override int processBlock(byte[] @in, int inOff, byte[] @out, int outOff)
		{
			this.processBytes(@in, inOff, cfbEngine.getBlockSize(), @out, outOff);

			return cfbEngine.getBlockSize();
		}

		public override byte calculateByte(byte b)
		{
			if (counter > 0 && counter % 1024 == 0)
			{
				BlockCipher @base = cfbEngine.getUnderlyingCipher();

				@base.init(false, key);

				byte[] nextKey = new byte[32];

				@base.processBlock(C, 0, nextKey, 0);
				@base.processBlock(C, 8, nextKey, 8);
				@base.processBlock(C, 16, nextKey, 16);
				@base.processBlock(C, 24, nextKey, 24);

				key = new KeyParameter(nextKey);

				@base.init(true, key);

				byte[] iv = cfbEngine.getCurrentIV();

				@base.processBlock(iv, 0, iv, 0);

				cfbEngine.init(forEncryption, new ParametersWithIV(key, iv));
			}

			counter++;

			return cfbEngine.calculateByte(b);
		}

		public override void reset()
		{
			counter = 0;
			cfbEngine.reset();
		}
	}

}