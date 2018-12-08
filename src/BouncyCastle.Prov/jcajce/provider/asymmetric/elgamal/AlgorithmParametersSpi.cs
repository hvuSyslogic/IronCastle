using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.elgamal
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ElGamalParameter = org.bouncycastle.asn1.oiw.ElGamalParameter;
	using BaseAlgorithmParameters = org.bouncycastle.jcajce.provider.symmetric.util.BaseAlgorithmParameters;
	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;

	public class AlgorithmParametersSpi : BaseAlgorithmParameters
	{
		internal ElGamalParameterSpec currentSpec;

		/// <summary>
		/// Return the X.509 ASN.1 structure ElGamalParameter.
		/// <pre>
		///  ElGamalParameter ::= SEQUENCE {
		///                   prime INTEGER, -- p
		///                   base INTEGER, -- g}
		/// </pre>
		/// </summary>
		public virtual byte[] engineGetEncoded()
		{
			ElGamalParameter elP = new ElGamalParameter(currentSpec.getP(), currentSpec.getG());

			try
			{
				return elP.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				throw new RuntimeException("Error encoding ElGamalParameters");
			}
		}

		public virtual byte[] engineGetEncoded(string format)
		{
			if (isASN1FormatString(format) || format.Equals("X.509", StringComparison.OrdinalIgnoreCase))
			{
				return engineGetEncoded();
			}

			return null;
		}

		public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
		{
			if (paramSpec == typeof(ElGamalParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return currentSpec;
			}
			else if (paramSpec == typeof(DHParameterSpec))
			{
				return new DHParameterSpec(currentSpec.getP(), currentSpec.getG());
			}

			throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
		}

		public virtual void engineInit(AlgorithmParameterSpec paramSpec)
		{
			if (!(paramSpec is ElGamalParameterSpec) && !(paramSpec is DHParameterSpec))
			{
				throw new InvalidParameterSpecException("DHParameterSpec required to initialise a ElGamal algorithm parameters object");
			}

			if (paramSpec is ElGamalParameterSpec)
			{
				this.currentSpec = (ElGamalParameterSpec)paramSpec;
			}
			else
			{
				DHParameterSpec s = (DHParameterSpec)paramSpec;

				this.currentSpec = new ElGamalParameterSpec(s.getP(), s.getG());
			}
		}

		public virtual void engineInit(byte[] @params)
		{
			try
			{
				ElGamalParameter elP = ElGamalParameter.getInstance(ASN1Primitive.fromByteArray(@params));

				currentSpec = new ElGamalParameterSpec(elP.getP(), elP.getG());
			}
			catch (ClassCastException)
			{
				throw new IOException("Not a valid ElGamal Parameter encoding.");
			}
			catch (ArrayIndexOutOfBoundsException)
			{
				throw new IOException("Not a valid ElGamal Parameter encoding.");
			}
		}

		public virtual void engineInit(byte[] @params, string format)
		{
			if (isASN1FormatString(format) || format.Equals("X.509", StringComparison.OrdinalIgnoreCase))
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
			return "ElGamal Parameters";
		}
	}

}