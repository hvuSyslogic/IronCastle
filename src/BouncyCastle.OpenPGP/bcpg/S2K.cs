namespace org.bouncycastle.bcpg
{


	/// <summary>
	/// Parameter specifier for the PGP string-to-key password based key derivation function.
	/// <para>
	/// In iterated mode, S2K takes a single byte iteration count specifier, which is converted to an
	/// actual iteration count using a formula that grows the iteration count exponentially as the byte
	/// value increases.
	/// </para>
	/// </para><para>
	/// e.g. <code>0x01</code> == 1088 iterations, and <code>0xFF</code> == 65,011,712 iterations.
	/// </p>
	/// </summary>
	public class S2K : BCPGObject
	{
		private const int EXPBIAS = 6;

		/// <summary>
		/// Simple key generation. A single non-salted iteration of a hash function </summary>
		public const int SIMPLE = 0;
		/// <summary>
		/// Salted key generation. A single iteration of a hash function with a (unique) salt </summary>
		public const int SALTED = 1;
		/// <summary>
		/// Salted and iterated key generation. Multiple iterations of a hash function, with a salt </summary>
		public const int SALTED_AND_ITERATED = 3;

		public const int GNU_DUMMY_S2K = 101;

		public const int GNU_PROTECTION_MODE_NO_PRIVATE_KEY = 1;
		public const int GNU_PROTECTION_MODE_DIVERT_TO_CARD = 2;

		internal int type;
		internal int algorithm;
		internal byte[] iv;
		internal int itCount = -1;
		internal int protectionMode = -1;

		public S2K(InputStream @in)
		{
			DataInputStream dIn = new DataInputStream(@in);

			type = dIn.read();
			algorithm = dIn.read();

			//
			// if this happens we have a dummy-S2K packet.
			//
			if (type != GNU_DUMMY_S2K)
			{
				if (type != 0)
				{
					iv = new byte[8];
					dIn.readFully(iv, 0, iv.Length);

					if (type == 3)
					{
						itCount = dIn.read();
					}
				}
			}
			else
			{
				dIn.read(); // G
				dIn.read(); // N
				dIn.read(); // U
				protectionMode = dIn.read(); // protection mode
			}
		}

		/// <summary>
		/// Constructs a specifier for a <seealso cref="#SIMPLE simple"/> S2K generation.
		/// </summary>
		/// <param name="algorithm"> the <seealso cref="HashAlgorithmTags digest algorithm"/> to use. </param>
		public S2K(int algorithm)
		{
			this.type = 0;
			this.algorithm = algorithm;
		}

		/// <summary>
		/// Constructs a specifier for a <seealso cref="#SALTED salted"/> S2K generation.
		/// </summary>
		/// <param name="algorithm"> the <seealso cref="HashAlgorithmTags digest algorithm"/> to use. </param>
		/// <param name="iv"> the salt to apply to input to the key generation. </param>
		public S2K(int algorithm, byte[] iv)
		{
			this.type = 1;
			this.algorithm = algorithm;
			this.iv = iv;
		}

		/// <summary>
		/// Constructs a specifier for a <seealso cref="#SALTED_AND_ITERATED salted and iterated"/> S2K generation.
		/// </summary>
		/// <param name="algorithm"> the <seealso cref="HashAlgorithmTags digest algorithm"/> to iterate. </param>
		/// <param name="iv"> the salt to apply to input to the key generation. </param>
		/// <param name="itCount"> the single byte iteration count specifier. </param>
		public S2K(int algorithm, byte[] iv, int itCount)
		{
			this.type = 3;
			this.algorithm = algorithm;
			this.iv = iv;
			this.itCount = itCount;
		}

		/// <summary>
		/// Gets the <seealso cref="HashAlgorithmTags digest algorithm"/> specified.
		/// </summary>
		public virtual int getType()
		{
			return type;
		}

		/// <summary>
		/// Gets the <seealso cref="HashAlgorithmTags hash algorithm"/> for this S2K.
		/// </summary>
		public virtual int getHashAlgorithm()
		{
			return algorithm;
		}

		/// <summary>
		/// Gets the iv/salt to use for the key generation.
		/// </summary>
		public virtual byte[] getIV()
		{
			return iv;
		}

		/// <summary>
		/// Gets the actual (expanded) iteration count.
		/// </summary>
		public virtual long getIterationCount()
		{
			return (16 + (itCount & 15)) << ((itCount >> 4) + EXPBIAS);
		}

		/// <summary>
		/// Gets the protection mode - only if GNU_DUMMY_S2K
		/// </summary>
		public virtual int getProtectionMode()
		{
			return protectionMode;
		}

		public override void encode(BCPGOutputStream @out)
		{
			@out.write(type);
			@out.write(algorithm);

			if (type != GNU_DUMMY_S2K)
			{
				if (type != 0)
				{
					@out.write(iv);
				}

				if (type == 3)
				{
					@out.write(itCount);
				}
			}
			else
			{
				@out.write('G');
				@out.write('N');
				@out.write('U');
				@out.write(protectionMode);
			}
		}
	}

}