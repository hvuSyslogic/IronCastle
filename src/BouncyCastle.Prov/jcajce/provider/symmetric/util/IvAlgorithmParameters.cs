using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{

	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using Arrays = org.bouncycastle.util.Arrays;

	public class IvAlgorithmParameters : BaseAlgorithmParameters
	{
		private byte[] iv;

		public virtual byte[] engineGetEncoded()
		{
			return engineGetEncoded("ASN.1");
		}

		public virtual byte[] engineGetEncoded(string format)
		{
			if (isASN1FormatString(format))
			{
				return (new DEROctetString(engineGetEncoded("RAW"))).getEncoded();
			}

			if (format.Equals("RAW"))
			{
				return Arrays.clone(iv);
			}

			return null;
		}

		public override AlgorithmParameterSpec localEngineGetParameterSpec(Class paramSpec)
		{
			if (paramSpec == typeof(IvParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return new IvParameterSpec(iv);
			}

			throw new InvalidParameterSpecException("unknown parameter spec passed to IV parameters object.");
		}

		public virtual void engineInit(AlgorithmParameterSpec paramSpec)
		{
			if (!(paramSpec is IvParameterSpec))
			{
				throw new InvalidParameterSpecException("IvParameterSpec required to initialise a IV parameters algorithm parameters object");
			}

			this.iv = ((IvParameterSpec)paramSpec).getIV();
		}

		public virtual void engineInit(byte[] @params)
		{
			//
			// check that we don't have a DER encoded octet string
			//
			if ((@params.Length % 8) != 0 && @params[0] == 0x04 && @params[1] == @params.Length - 2)
			{
				ASN1OctetString oct = (ASN1OctetString)ASN1Primitive.fromByteArray(@params);

				@params = oct.getOctets();
			}

			this.iv = Arrays.clone(@params);
		}

		public virtual void engineInit(byte[] @params, string format)
		{
			if (isASN1FormatString(format))
			{
				try
				{
					ASN1OctetString oct = (ASN1OctetString)ASN1Primitive.fromByteArray(@params);

					engineInit(oct.getOctets());
				}
				catch (Exception e)
				{
					throw new IOException("Exception decoding: " + e);
				}

				return;
			}

			if (format.Equals("RAW"))
			{
				engineInit(@params);
				return;
			}

			throw new IOException("Unknown parameters format in IV parameters object");
		}

		public virtual string engineToString()
		{
			return "IV Parameters";
		}
	}

}