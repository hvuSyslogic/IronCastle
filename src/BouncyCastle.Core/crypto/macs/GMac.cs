using org.bouncycastle.crypto.modes;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
				
	/// <summary>
	/// The GMAC specialisation of Galois/Counter mode (GCM) detailed in NIST Special Publication
	/// 800-38D.
	/// <para>
	/// GMac is an invocation of the GCM mode where no data is encrypted (i.e. all input data to the Mac
	/// is processed as additional authenticated data with the underlying GCM block cipher).
	/// </para>
	/// </summary>
	public class GMac : Mac
	{
		private readonly GCMBlockCipher cipher;
		private readonly int macSizeBits;

		/// <summary>
		/// Creates a GMAC based on the operation of a block cipher in GCM mode.
		/// <para>
		/// This will produce an authentication code the length of the block size of the cipher.
		/// 
		/// </para>
		/// </summary>
		/// <param name="cipher">
		///            the cipher to be used in GCM mode to generate the MAC. </param>

		public GMac(GCMBlockCipher cipher)
		{
			// use of this confused flow analyser in some earlier JDKs
			this.cipher = cipher;
			this.macSizeBits = 128;
		}

		/// <summary>
		/// Creates a GMAC based on the operation of a 128 bit block cipher in GCM mode.
		/// </summary>
		/// <param name="macSizeBits">
		///            the mac size to generate, in bits. Must be a multiple of 8 and &gt;= 32 and &lt;= 128.
		///            Sizes less than 96 are not recommended, but are supported for specialized applications. </param>
		/// <param name="cipher">
		///            the cipher to be used in GCM mode to generate the MAC. </param>

		public GMac(GCMBlockCipher cipher, int macSizeBits)
		{
			this.cipher = cipher;
			this.macSizeBits = macSizeBits;
		}

		/// <summary>
		/// Initialises the GMAC - requires a <seealso cref="ParametersWithIV"/> providing a <seealso cref="KeyParameter"/>
		/// and a nonce.
		/// </summary>

		public virtual void init(CipherParameters @params)
		{
			if (@params is ParametersWithIV)
			{

				ParametersWithIV param = (ParametersWithIV)@params;


				byte[] iv = param.getIV();

				KeyParameter keyParam = (KeyParameter)param.getParameters();

				// GCM is always operated in encrypt mode to calculate MAC
				cipher.init(true, new AEADParameters(keyParam, macSizeBits, iv));
			}
			else
			{
				throw new IllegalArgumentException("GMAC requires ParametersWithIV");
			}
		}

		public virtual string getAlgorithmName()
		{
			return cipher.getUnderlyingCipher().getAlgorithmName() + "-GMAC";
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