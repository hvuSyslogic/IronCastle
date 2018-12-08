using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.macs
{
	using SkeinEngine = org.bouncycastle.crypto.digests.SkeinEngine;
	using ThreefishEngine = org.bouncycastle.crypto.engines.ThreefishEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using SkeinParameters = org.bouncycastle.crypto.@params.SkeinParameters;

	/// <summary>
	/// Implementation of the Skein parameterised MAC function in 256, 512 and 1024 bit block sizes,
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
	public class SkeinMac : Mac
	{
		/// <summary>
		/// 256 bit block size - Skein MAC-256
		/// </summary>
		public static readonly int SKEIN_256 = SkeinEngine.SKEIN_256;
		/// <summary>
		/// 512 bit block size - Skein MAC-512
		/// </summary>
		public static readonly int SKEIN_512 = SkeinEngine.SKEIN_512;
		/// <summary>
		/// 1024 bit block size - Skein MAC-1024
		/// </summary>
		public static readonly int SKEIN_1024 = SkeinEngine.SKEIN_1024;

		private SkeinEngine engine;

		/// <summary>
		/// Constructs a Skein MAC with an internal state size and output size.
		/// </summary>
		/// <param name="stateSizeBits">  the internal state size in bits - one of <seealso cref="#SKEIN_256"/>, <seealso cref="#SKEIN_512"/> or
		///                       <seealso cref="#SKEIN_1024"/>. </param>
		/// <param name="digestSizeBits"> the output/MAC size to produce in bits, which must be an integral number of bytes. </param>
		public SkeinMac(int stateSizeBits, int digestSizeBits)
		{
			this.engine = new SkeinEngine(stateSizeBits, digestSizeBits);
		}

		public SkeinMac(SkeinMac mac)
		{
			this.engine = new SkeinEngine(mac.engine);
		}

		public virtual string getAlgorithmName()
		{
			return "Skein-MAC-" + (engine.getBlockSize() * 8) + "-" + (engine.getOutputSize() * 8);
		}

		/// <summary>
		/// Initialises the Skein digest with the provided parameters.<br>
		/// See <seealso cref="SkeinParameters"/> for details on the parameterisation of the Skein hash function.
		/// </summary>
		/// <param name="params"> an instance of <seealso cref="SkeinParameters"/> or <seealso cref="KeyParameter"/>. </param>
		public virtual void init(CipherParameters @params)
		{
			SkeinParameters skeinParameters;
			if (@params is SkeinParameters)
			{
				skeinParameters = (SkeinParameters)@params;
			}
			else if (@params is KeyParameter)
			{
				skeinParameters = (new SkeinParameters.Builder()).setKey(((KeyParameter)@params).getKey()).build();
			}
			else
			{
				throw new IllegalArgumentException("Invalid parameter passed to Skein MAC init - " + @params.GetType().getName());
			}
			if (skeinParameters.getKey() == null)
			{
				throw new IllegalArgumentException("Skein MAC requires a key parameter.");
			}
			engine.init(skeinParameters);
		}

		public virtual int getMacSize()
		{
			return engine.getOutputSize();
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