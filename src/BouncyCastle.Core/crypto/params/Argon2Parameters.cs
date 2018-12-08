namespace org.bouncycastle.crypto.@params
{
	using Arrays = org.bouncycastle.util.Arrays;

	public class Argon2Parameters
	{
		public const int ARGON2_d = 0x00;
		public const int ARGON2_i = 0x01;
		public const int ARGON2_id = 0x02;

		public const int ARGON2_VERSION_10 = 0x10;
		public const int ARGON2_VERSION_13 = 0x13;

		private const int DEFAULT_ITERATIONS = 3;
		private const int DEFAULT_MEMORY_COST = 12;
		private const int DEFAULT_LANES = 1;
		private const int DEFAULT_TYPE = ARGON2_i;
		private const int DEFAULT_VERSION = ARGON2_VERSION_13;

		public class Builder
		{
			internal byte[] salt;
			internal byte[] secret;
			internal byte[] additional;

			internal int iterations;
			internal int memory;
			internal int lanes;

			internal int version;
			internal readonly int type;

			internal CharToByteConverter converter = PasswordConverter.UTF8;

			public Builder() : this(DEFAULT_TYPE)
			{
			}

			public Builder(int type)
			{
				this.type = type;
				this.lanes = DEFAULT_LANES;
				this.memory = 1 << DEFAULT_MEMORY_COST;
				this.iterations = DEFAULT_ITERATIONS;
				this.version = DEFAULT_VERSION;
			}

			public virtual Builder withParallelism(int parallelism)
			{
				this.lanes = parallelism;
				return this;
			}

			public virtual Builder withSalt(byte[] salt)
			{
				this.salt = Arrays.clone(salt);
				return this;
			}

			public virtual Builder withSecret(byte[] secret)
			{
				this.secret = Arrays.clone(secret);
				return this;
			}

			public virtual Builder withAdditional(byte[] additional)
			{
				this.additional = Arrays.clone(additional);
				return this;
			}

			public virtual Builder withIterations(int iterations)
			{
				this.iterations = iterations;
				return this;
			}


			public virtual Builder withMemoryAsKB(int memory)
			{
				this.memory = memory;
				return this;
			}


			public virtual Builder withMemoryPowOfTwo(int memory)
			{
				this.memory = 1 << memory;
				return this;
			}

			public virtual Builder withVersion(int version)
			{
				this.version = version;
				return this;
			}

			public virtual Builder withCharToByteConverter(CharToByteConverter converter)
			{
				this.converter = converter;
				return this;
			}

			public virtual Argon2Parameters build()
			{
				return new Argon2Parameters(type, salt, secret, additional, iterations, memory, lanes, version, converter);
			}

			public virtual void clear()
			{
				Arrays.clear(salt);
				Arrays.clear(secret);
				Arrays.clear(additional);
			}
		}

		private readonly byte[] salt;
		private readonly byte[] secret;
		private readonly byte[] additional;

		private readonly int iterations;
		private readonly int memory;
		private readonly int lanes;

		private readonly int version;
		private readonly int type;
		private readonly CharToByteConverter converter;

		private Argon2Parameters(int type, byte[] salt, byte[] secret, byte[] additional, int iterations, int memory, int lanes, int version, CharToByteConverter converter)
		{

			this.salt = Arrays.clone(salt);
			this.secret = Arrays.clone(secret);
			this.additional = Arrays.clone(additional);
			this.iterations = iterations;
			this.memory = memory;
			this.lanes = lanes;
			this.version = version;
			this.type = type;
			this.converter = converter;
		}

		public virtual byte[] getSalt()
		{
			return Arrays.clone(salt);
		}

		public virtual byte[] getSecret()
		{
			return Arrays.clone(secret);
		}

		public virtual byte[] getAdditional()
		{
			return Arrays.clone(additional);
		}

		public virtual int getIterations()
		{
			return iterations;
		}

		public virtual int getMemory()
		{
			return memory;
		}

		public virtual int getLanes()
		{
			return lanes;
		}

		public virtual int getVersion()
		{
			return version;
		}

		public virtual int getType()
		{
			return type;
		}

		public virtual CharToByteConverter getCharToByteConverter()
		{
			return converter;
		}

		public virtual void clear()
		{
			Arrays.clear(salt);
			Arrays.clear(secret);
			Arrays.clear(additional);
		}
	}

}