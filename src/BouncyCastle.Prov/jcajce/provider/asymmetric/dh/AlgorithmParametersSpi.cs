using org.bouncycastle.asn1;

namespace org.bouncycastle.jcajce.provider.asymmetric.dh
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DHParameter = org.bouncycastle.asn1.pkcs.DHParameter;

	public class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
		internal DHParameterSpec currentSpec;

		public virtual bool isASN1FormatString(string format)
		{
			return string.ReferenceEquals(format, null) || format.Equals("ASN.1");
		}

		public virtual AlgorithmParameterSpec engineGetParameterSpec(Class paramSpec)
		{
			if (paramSpec == null)
			{
				throw new NullPointerException("argument to getParameterSpec must not be null");
			}

			return localEngineGetParameterSpec(paramSpec);
		}




			/// <summary>
			/// Return the PKCS#3 ASN.1 structure DHParameter.
			/// <para>
			/// <pre>
			///  DHParameter ::= SEQUENCE {
			///                   prime INTEGER, -- p
			///                   base INTEGER, -- g
			///                   privateValueLength INTEGER OPTIONAL}
			/// </pre>
			/// </para>
			/// </summary>
			public virtual byte[] engineGetEncoded()
			{
				DHParameter dhP = new DHParameter(currentSpec.getP(), currentSpec.getG(), currentSpec.getL());

				try
				{
					return dhP.getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException)
				{
					throw new RuntimeException("Error encoding DHParameters");
				}
			}

			public virtual byte[] engineGetEncoded(string format)
			{
				if (isASN1FormatString(format))
				{
					return engineGetEncoded();
				}

				return null;
			}

			public virtual AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
			{
				if (paramSpec == typeof(DHParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
				{
					return currentSpec;
				}

				throw new InvalidParameterSpecException("unknown parameter spec passed to DH parameters object.");
			}

			public virtual void engineInit(AlgorithmParameterSpec paramSpec)
			{
				if (!(paramSpec is DHParameterSpec))
				{
					throw new InvalidParameterSpecException("DHParameterSpec required to initialise a Diffie-Hellman algorithm parameters object");
				}

				this.currentSpec = (DHParameterSpec)paramSpec;
			}

			public virtual void engineInit(byte[] @params)
			{
				try
				{
					DHParameter dhP = DHParameter.getInstance(@params);

					if (dhP.getL() != null)
					{
						currentSpec = new DHParameterSpec(dhP.getP(), dhP.getG(), dhP.getL().intValue());
					}
					else
					{
						currentSpec = new DHParameterSpec(dhP.getP(), dhP.getG());
					}
				}
				catch (ClassCastException)
				{
					throw new IOException("Not a valid DH Parameter encoding.");
				}
				catch (ArrayIndexOutOfBoundsException)
				{
					throw new IOException("Not a valid DH Parameter encoding.");
				}
			}

			public virtual void engineInit(byte[] @params, string format)
			{
				if (isASN1FormatString(format))
				{
					engineInit(@params);
				}
				else
				{
					throw new IOException("Unknown parameter format " + format);
				}
			}

			public virtual string engineToString()
			{
				return "Diffie-Hellman Parameters";
			}
	}

}