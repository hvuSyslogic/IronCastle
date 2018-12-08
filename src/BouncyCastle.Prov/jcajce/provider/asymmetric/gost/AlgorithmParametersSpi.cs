using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.gost
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using GOST3410PublicKeyAlgParameters = org.bouncycastle.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
	using GOST3410ParameterSpec = org.bouncycastle.jce.spec.GOST3410ParameterSpec;
	using GOST3410PublicKeyParameterSetSpec = org.bouncycastle.jce.spec.GOST3410PublicKeyParameterSetSpec;

	public class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
		internal GOST3410ParameterSpec currentSpec;

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
		/// Return the X.509 ASN.1 structure GOST3410Parameter.
		/// <pre>
		///  GOST3410Parameter ::= SEQUENCE {
		///                   prime INTEGER, -- p
		///                   subprime INTEGER, -- q
		///                   base INTEGER, -- a}
		/// </pre>
		/// </summary>
		public virtual byte[] engineGetEncoded()
		{
			GOST3410PublicKeyAlgParameters gost3410P = new GOST3410PublicKeyAlgParameters(new ASN1ObjectIdentifier(currentSpec.getPublicKeyParamSetOID()), new ASN1ObjectIdentifier(currentSpec.getDigestParamSetOID()), new ASN1ObjectIdentifier(currentSpec.getEncryptionParamSetOID()));

			try
			{
				return gost3410P.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				throw new RuntimeException("Error encoding GOST3410Parameters");
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

		public virtual AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
		{
			if (paramSpec == typeof(GOST3410PublicKeyParameterSetSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return currentSpec;
			}

			throw new InvalidParameterSpecException("unknown parameter spec passed to GOST3410 parameters object.");
		}

		public virtual void engineInit(AlgorithmParameterSpec paramSpec)
		{
			if (!(paramSpec is GOST3410ParameterSpec))
			{
				throw new InvalidParameterSpecException("GOST3410ParameterSpec required to initialise a GOST3410 algorithm parameters object");
			}

			this.currentSpec = (GOST3410ParameterSpec)paramSpec;
		}

		public virtual void engineInit(byte[] @params)
		{
			try
			{
				ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(@params);

				this.currentSpec = GOST3410ParameterSpec.fromPublicKeyAlg(new GOST3410PublicKeyAlgParameters(seq));
			}
			catch (ClassCastException)
			{
				throw new IOException("Not a valid GOST3410 Parameter encoding.");
			}
			catch (ArrayIndexOutOfBoundsException)
			{
				throw new IOException("Not a valid GOST3410 Parameter encoding.");
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
			return "GOST3410 Parameters";
		}

	}

}