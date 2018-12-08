﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
	using KGCMBlockCipher = org.bouncycastle.crypto.modes.KGCMBlockCipher;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;

	/// <summary>
	/// The GMAC specialisation of Galois/Counter mode (GCM) detailed in NIST Special Publication
	/// 800-38D as adapted for the Kalyna version of GCM.
	/// <para>
	/// KGMac is an invocation of the KGCM mode where no data is encrypted (i.e. all input data to the Mac
	/// is processed as additional authenticated data with the underlying KGCM block cipher).
	/// </para>
	/// </summary>
	public class KGMac : Mac
	{
		private readonly KGCMBlockCipher cipher;
		private readonly int macSizeBits;

		/// <summary>
		/// Creates a KGMAC based on the operation of a block cipher in GCM mode.
		/// <para>
		/// This will produce an authentication code the length of the block size of the cipher.
		/// 
		/// </para>
		/// </summary>
		/// <param name="cipher">
		///            the cipher to be used in GCM mode to generate the MAC. </param>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public KGMac(final org.bouncycastle.crypto.modes.KGCMBlockCipher cipher)
		public KGMac(KGCMBlockCipher cipher)
		{
			// use of this confused flow analyser in some earlier JDKs
			this.cipher = cipher;
			this.macSizeBits = cipher.getUnderlyingCipher().getBlockSize() * 8;
		}

		/// <summary>
		/// Creates a GMAC based on the operation of a 128 bit block cipher in GCM mode.
		/// </summary>
		/// <param name="macSizeBits">
		///            the mac size to generate, in bits. Must be a multiple of 8 and &gt;= 32 and &lt;= 128.
		///            Sizes less than 96 are not recommended, but are supported for specialized applications. </param>
		/// <param name="cipher">
		///            the cipher to be used in GCM mode to generate the MAC. </param>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public KGMac(final org.bouncycastle.crypto.modes.KGCMBlockCipher cipher, final int macSizeBits)
		public KGMac(KGCMBlockCipher cipher, int macSizeBits)
		{
			this.cipher = cipher;
			this.macSizeBits = macSizeBits;
		}

		/// <summary>
		/// Initialises the GMAC - requires a <seealso cref="ParametersWithIV"/> providing a <seealso cref="KeyParameter"/>
		/// and a nonce.
		/// </summary>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public void init(final org.bouncycastle.crypto.CipherParameters params) throws IllegalArgumentException
		public virtual void init(CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.ParametersWithIV param = (org.bouncycastle.crypto.params.ParametersWithIV)params;
				ParametersWithIV param = (ParametersWithIV)@params;

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] iv = param.getIV();
				byte[] iv = param.getIV();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KeyParameter keyParam = (org.bouncycastle.crypto.params.KeyParameter)param.getParameters();
				KeyParameter keyParam = (KeyParameter)param.getParameters();

				// GCM is always operated in encrypt mode to calculate MAC
				cipher.init(true, new AEADParameters(keyParam, macSizeBits, iv));
			}
			else
			{
				throw new IllegalArgumentException("KGMAC requires ParametersWithIV");
			}
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getUnderlyingCipher().getAlgorithmName() + "-KGMAC";
		}

		public virtual int getMacSize()
		{
			return macSizeBits / 8;
		}

		public virtual void update(byte @in)
		{
			cipher.processAADByte(@in);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			cipher.processAADBytes(@in, inOff, len);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			try
			{
				return cipher.doFinal(@out, outOff);
			}
			catch (InvalidCipherTextException e)
			{
				// Impossible in encrypt mode
				throw new IllegalStateException(e.ToString());
			}
		}

		public virtual void reset()
		{
			cipher.reset();
		}
	}

}