namespace org.bouncycastle.cms.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using InputExpander = org.bouncycastle.@operator.InputExpander;
	using InputExpanderProvider = org.bouncycastle.@operator.InputExpanderProvider;
	using StreamOverflowException = org.bouncycastle.util.io.StreamOverflowException;

	public class ZlibExpanderProvider : InputExpanderProvider
	{
		private readonly long limit;

		/// <summary>
		/// Base constructor. Create an expander which will not limit the size of any objects expanded in the stream.
		/// </summary>
		public ZlibExpanderProvider()
		{
			this.limit = -1;
		}

		/// <summary>
		/// Create a provider which caps the number of expanded bytes that can be produced when the
		/// compressed stream is parsed.
		/// </summary>
		/// <param name="limit"> max number of bytes allowed in an expanded stream. </param>
		public ZlibExpanderProvider(long limit)
		{
			this.limit = limit;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.InputExpander get(final org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm)
		public virtual InputExpander get(AlgorithmIdentifier algorithm)
		{
			return new InputExpanderAnonymousInnerClass(this, algorithm);
		}

		public class InputExpanderAnonymousInnerClass : InputExpander
		{
			private readonly ZlibExpanderProvider outerInstance;

			private AlgorithmIdentifier algorithm;

			public InputExpanderAnonymousInnerClass(ZlibExpanderProvider outerInstance, AlgorithmIdentifier algorithm)
			{
				this.outerInstance = outerInstance;
				this.algorithm = algorithm;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algorithm;
			}

			public InputStream getInputStream(InputStream comIn)
			{
				InputStream s = new InflaterInputStream(comIn);
				if (outerInstance.limit >= 0)
				{
					s = new LimitedInputStream(s, outerInstance.limit);
				}
				return s;
			}
		}

		public class LimitedInputStream : FilterInputStream
		{
			internal long remaining;

			public LimitedInputStream(InputStream input, long limit) : base(input)
			{

				this.remaining = limit;
			}

			public virtual int read()
			{
				// Only a single 'extra' byte will ever be read
				if (remaining >= 0)
				{
					int b = base.@in.read();
					if (b < 0 || --remaining >= 0)
					{
						return b;
					}
				}

				throw new StreamOverflowException("expanded byte limit exceeded");
			}

			public virtual int read(byte[] buf, int off, int len)
			{
				if (len < 1)
				{
					// This will give correct exceptions/returns for strange lengths
					return base.read(buf, off, len);
				}

				if (remaining < 1)
				{
					// Will either return EOF or throw exception
					read();
					return -1;
				}

				/*
				 * Limit the underlying request to 'remaining' bytes. This ensures the
				 * caller will see the full 'limit' bytes before getting an exception.
				 * Also, only one extra byte will ever be read.
				 */
				int actualLen = (remaining > len ? len : (int)remaining);
				int numRead = base.@in.read(buf, off, actualLen);
				if (numRead > 0)
				{
					remaining -= numRead;
				}
				return numRead;
			}
		}
	}

}