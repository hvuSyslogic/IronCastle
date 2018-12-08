using org.bouncycastle.asn1.cmp;

namespace org.bouncycastle.cert.crmf
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using CMPObjectIdentifiers = org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
	using PBMParameter = org.bouncycastle.asn1.cmp.PBMParameter;
	using IANAObjectIdentifiers = org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using RuntimeOperatorException = org.bouncycastle.@operator.RuntimeOperatorException;
	using Strings = org.bouncycastle.util.Strings;

	public class PKMACBuilder
	{
		private AlgorithmIdentifier owf;
		private int iterationCount;
		private AlgorithmIdentifier mac;
		private int saltLength = 20;
		private SecureRandom random;
		private PKMACValuesCalculator calculator;
		private PBMParameter parameters;
		private int maxIterations;

		public PKMACBuilder(PKMACValuesCalculator calculator) : this(new AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers_Fields.idSHA1), 1000, new AlgorithmIdentifier(org.bouncycastle.asn1.iana.IANAObjectIdentifiers_Fields.hmacSHA1, DERNull.INSTANCE), calculator)
		{
		}

		/// <summary>
		/// Create a PKMAC builder enforcing a ceiling on the maximum iteration count.
		/// </summary>
		/// <param name="calculator">     supporting calculator </param>
		/// <param name="maxIterations">  max allowable value for iteration count. </param>
		public PKMACBuilder(PKMACValuesCalculator calculator, int maxIterations)
		{
			this.maxIterations = maxIterations;
			this.calculator = calculator;
		}

		private PKMACBuilder(AlgorithmIdentifier hashAlgorithm, int iterationCount, AlgorithmIdentifier macAlgorithm, PKMACValuesCalculator calculator)
		{
			this.owf = hashAlgorithm;
			this.iterationCount = iterationCount;
			this.mac = macAlgorithm;
			this.calculator = calculator;
		}

		/// <summary>
		/// Set the salt length in octets.
		/// </summary>
		/// <param name="saltLength"> length in octets of the salt to be generated. </param>
		/// <returns> the generator </returns>
		public virtual PKMACBuilder setSaltLength(int saltLength)
		{
			if (saltLength < 8)
			{
				throw new IllegalArgumentException("salt length must be at least 8 bytes");
			}

			this.saltLength = saltLength;

			return this;
		}

		public virtual PKMACBuilder setIterationCount(int iterationCount)
		{
			if (iterationCount < 100)
			{
				throw new IllegalArgumentException("iteration count must be at least 100");
			}
			checkIterationCountCeiling(iterationCount);

			this.iterationCount = iterationCount;

			return this;
		}

		public virtual PKMACBuilder setSecureRandom(SecureRandom random)
		{
			this.random = random;

			return this;
		}

		public virtual PKMACBuilder setParameters(PBMParameter parameters)
		{
			checkIterationCountCeiling(parameters.getIterationCount().getValue().intValue());

			this.parameters = parameters;

			return this;
		}

		public virtual MacCalculator build(char[] password)
		{
			if (parameters != null)
			{
				return genCalculator(parameters, password);
			}
			else
			{
				byte[] salt = new byte[saltLength];

				if (random == null)
				{
					this.random = new SecureRandom();
				}

				random.nextBytes(salt);

				return genCalculator(new PBMParameter(salt, owf, iterationCount, mac), password);
			}
		}

		private void checkIterationCountCeiling(int iterationCount)
		{
			if (maxIterations > 0 && iterationCount > maxIterations)
			{
				throw new IllegalArgumentException("iteration count exceeds limit (" + iterationCount + " > " + maxIterations + ")");
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private org.bouncycastle.operator.MacCalculator genCalculator(final org.bouncycastle.asn1.cmp.PBMParameter params, char[] password) throws CRMFException
		private MacCalculator genCalculator(PBMParameter @params, char[] password)
		{
			// From RFC 4211
			//
			//   1.  Generate a random salt value S
			//
			//   2.  Append the salt to the pw.  K = pw || salt.
			//
			//   3.  Hash the value of K.  K = HASH(K)
			//
			//   4.  Iter = Iter - 1.  If Iter is greater than zero.  Goto step 3.
			//
			//   5.  Compute an HMAC as documented in [HMAC].
			//
			//       MAC = HASH( K XOR opad, HASH( K XOR ipad, data) )
			//
			//       Where opad and ipad are defined in [HMAC].
			byte[] pw = Strings.toUTF8ByteArray(password);
			byte[] salt = @params.getSalt().getOctets();
			byte[] K = new byte[pw.Length + salt.Length];

			JavaSystem.arraycopy(pw, 0, K, 0, pw.Length);
			JavaSystem.arraycopy(salt, 0, K, pw.Length, salt.Length);

			calculator.setup(@params.getOwf(), @params.getMac());

			int iter = @params.getIterationCount().getValue().intValue();
			do
			{
				K = calculator.calculateDigest(K);
			} while (--iter > 0);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] key = K;
			byte[] key = K;

			return new MacCalculatorAnonymousInnerClass(this, @params, key);
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private readonly PKMACBuilder outerInstance;

			private PBMParameter @params;
			private byte[] key;

			public MacCalculatorAnonymousInnerClass(PKMACBuilder outerInstance, PBMParameter @params, byte[] key)
			{
				this.outerInstance = outerInstance;
				this.@params = @params;
				this.key = key;
				bOut = new ByteArrayOutputStream();
			}

			internal ByteArrayOutputStream bOut;

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(CMPObjectIdentifiers_Fields.passwordBasedMac, @params);
			}

			public GenericKey getKey()
			{
				return new GenericKey(getAlgorithmIdentifier(), key);
			}

			public OutputStream getOutputStream()
			{
				return bOut;
			}

			public byte[] getMac()
			{
				try
				{
					return outerInstance.calculator.calculateMac(key, bOut.toByteArray());
				}
				catch (CRMFException e)
				{
					throw new RuntimeOperatorException("exception calculating mac: " + e.Message, e);
				}
			}
		}
	}

}