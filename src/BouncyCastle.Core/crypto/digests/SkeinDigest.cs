namespace org.bouncycastle.crypto.digests
{
	using ThreefishEngine = org.bouncycastle.crypto.engines.ThreefishEngine;
	using SkeinParameters = org.bouncycastle.crypto.@params.SkeinParameters;
	using Memoable = org.bouncycastle.util.Memoable;

	/// <summary>
	/// Implementation of the Skein parameterised hash function in 256, 512 and 1024 bit block sizes,
	/// based on the <seealso cref="ThreefishEngine Threefish"/> tweakable block cipher.
	/// <para>
	/// This is the 1.3 version of Skein defined in the Skein hash function submission to the NIST SHA-3
	/// competition in October 2010.
	/// </para>
	/// <para>
	/// Skein was designed by Niels Ferguson - Stefan Lucks - Bruce Schneier - Doug Whiting - Mihir
	/// Bellare - Tadayoshi Kohno - Jon Callas - Jesse Walker.
	/// 
	/// </para>
	/// </summary>
	/// <seealso cref= SkeinEngine </seealso>
	/// <seealso cref= SkeinParameters </seealso>
	public class SkeinDigest : ExtendedDigest, Memoable
	{
		/// <summary>
		/// 256 bit block size - Skein-256
		/// </summary>
		public static readonly int SKEIN_256 = SkeinEngine.SKEIN_256;
		/// <summary>
		/// 512 bit block size - Skein-512
		/// </summary>
		public static readonly int SKEIN_512 = SkeinEngine.SKEIN_512;
		/// <summary>
		/// 1024 bit block size - Skein-1024
		/// </summary>
		public static readonly int SKEIN_1024 = SkeinEngine.SKEIN_1024;

		private SkeinEngine engine;

		/// <summary>
		/// Constructs a Skein digest with an internal state size and output size.
		/// </summary>
		/// <param name="stateSizeBits">  the internal state size in bits - one of <seealso cref="#SKEIN_256"/>, <seealso cref="#SKEIN_512"/> or
		///                       <seealso cref="#SKEIN_1024"/>. </param>
		/// <param name="digestSizeBits"> the output/digest size to produce in bits, which must be an integral number of
		///                       bytes. </param>
		public SkeinDigest(int stateSizeBits, int digestSizeBits)
		{
			this.engine = new SkeinEngine(stateSizeBits, digestSizeBits);
			init(null);
		}

		public SkeinDigest(SkeinDigest digest)
		{
			this.engine = new SkeinEngine(digest.engine);
		}

		public virtual void reset(Memoable other)
		{
			SkeinDigest d = (SkeinDigest)other;
			engine.reset(d.engine);
		}

		public virtual Memoable copy()
		{
			return new SkeinDigest(this);
		}

		public virtual string getAlgorithmName()
		{
			return "Skein-" + (engine.getBlockSize() * 8) + "-" + (engine.getOutputSize() * 8);
		}

		public virtual int getDigestSize()
		{
			return engine.getOutputSize();
		}

		public virtual int getByteLength()
		{
			return engine.getBlockSize();
		}

		/// <summary>
		/// Optionally initialises the Skein digest with the provided parameters.<br>
		/// See <seealso cref="SkeinParameters"/> for details on the parameterisation of the Skein hash function.
		/// </summary>
		/// <param name="params"> the parameters to apply to this engine, or <code>null</code> to use no parameters. </param>
		public virtual void init(SkeinParameters @params)
		{
			engine.init(@params);
		}

		public virtual void reset()
		{
			engine.reset();
		}

		public virtual void update(byte @in)
		{
			engine.update(@in);
		}

		public virtual void update(byte[] @in, int inOff, int len)
		{
			engine.update(@in, inOff, len);
		}

		public virtual int doFinal(byte[] @out, int outOff)
		{
			return engine.doFinal(@out, outOff);
		}

	}

}