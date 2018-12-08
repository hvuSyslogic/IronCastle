using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.dsa
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DSAParameter = org.bouncycastle.asn1.x509.DSAParameter;

	public class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
		internal DSAParameterSpec currentSpec;

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
		/// Return the X.509 ASN.1 structure DSAParameter.
		/// <pre>
		///  DSAParameter ::= SEQUENCE {
		///                   prime INTEGER, -- p
		///                   subprime INTEGER, -- q
		///                   base INTEGER, -- g}
		/// </pre>
		/// </summary>
		public virtual byte[] engineGetEncoded()
		{
			DSAParameter dsaP = new DSAParameter(currentSpec.getP(), currentSpec.getQ(), currentSpec.getG());

			try
			{
				return dsaP.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				throw new RuntimeException("Error encoding DSAParameters");
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
			if (paramSpec == typeof(DSAParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return currentSpec;
			}

			throw new InvalidParameterSpecException("unknown parameter spec passed to DSA parameters object.");
		}

		public virtual void engineInit(AlgorithmParameterSpec paramSpec)
		{
			if (!(paramSpec is DSAParameterSpec))
			{
				throw new InvalidParameterSpecException("DSAParameterSpec required to initialise a DSA algorithm parameters object");
			}

			this.currentSpec = (DSAParameterSpec)paramSpec;
		}

		public virtual void engineInit(byte[] @params)
		{
			try
			{
				DSAParameter dsaP = DSAParameter.getInstance(ASN1Primitive.fromByteArray(@params));

				currentSpec = new DSAParameterSpec(dsaP.getP(), dsaP.getQ(), dsaP.getG());
			}
			catch (ClassCastException)
			{
				throw new IOException("Not a valid DSA Parameter encoding.");
			}
			catch (ArrayIndexOutOfBoundsException)
			{
				throw new IOException("Not a valid DSA Parameter encoding.");
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
			return "DSA Parameters";
		}
	}

}