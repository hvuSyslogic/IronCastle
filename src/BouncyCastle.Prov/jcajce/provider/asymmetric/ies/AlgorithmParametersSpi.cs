using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.jcajce.provider.asymmetric.ies
{

	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1TaggedObject = org.bouncycastle.asn1.ASN1TaggedObject;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using DERTaggedObject = org.bouncycastle.asn1.DERTaggedObject;
	using IESParameterSpec = org.bouncycastle.jce.spec.IESParameterSpec;

	public class AlgorithmParametersSpi : java.security.AlgorithmParametersSpi
	{
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

		internal IESParameterSpec currentSpec;

		/// <summary>
		/// in the absence of a standard way of doing it this will do for
		/// now...
		/// </summary>
		public virtual byte[] engineGetEncoded()
		{
			try
			{
				ASN1EncodableVector v = new ASN1EncodableVector();

				if (currentSpec.getDerivationV() != null)
				{
					v.add(new DERTaggedObject(false, 0, new DEROctetString(currentSpec.getDerivationV())));
				}
				if (currentSpec.getEncodingV() != null)
				{
					v.add(new DERTaggedObject(false, 1, new DEROctetString(currentSpec.getEncodingV())));
				}
				v.add(new ASN1Integer(currentSpec.getMacKeySize()));
				if (currentSpec.getNonce() != null)
				{
					ASN1EncodableVector cV = new ASN1EncodableVector();

					cV.add(new ASN1Integer(currentSpec.getCipherKeySize()));
					cV.add(new ASN1Integer(currentSpec.getNonce()));

					v.add(new DERSequence(cV));
				}
				return (new DERSequence(v)).getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException)
			{
				throw new RuntimeException("Error encoding IESParameters");
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
			if (paramSpec == typeof(IESParameterSpec) || paramSpec == typeof(AlgorithmParameterSpec))
			{
				return currentSpec;
			}

			throw new InvalidParameterSpecException("unknown parameter spec passed to ElGamal parameters object.");
		}

		public virtual void engineInit(AlgorithmParameterSpec paramSpec)
		{
			if (!(paramSpec is IESParameterSpec))
			{
				throw new InvalidParameterSpecException("IESParameterSpec required to initialise a IES algorithm parameters object");
			}

			this.currentSpec = (IESParameterSpec)paramSpec;
		}

		public virtual void engineInit(byte[] @params)
		{
			try
			{
				ASN1Sequence s = (ASN1Sequence)ASN1Primitive.fromByteArray(@params);

				if (s.size() == 1)
				{
					this.currentSpec = new IESParameterSpec(null, null, ASN1Integer.getInstance(s.getObjectAt(0)).getValue().intValue());
				}
				else if (s.size() == 2)
				{
					ASN1TaggedObject tagged = ASN1TaggedObject.getInstance(s.getObjectAt(0));

					if (tagged.getTagNo() == 0)
					{
						this.currentSpec = new IESParameterSpec(ASN1OctetString.getInstance(tagged, false).getOctets(), null, ASN1Integer.getInstance(s.getObjectAt(1)).getValue().intValue());
					}
					else
					{
						this.currentSpec = new IESParameterSpec(null, ASN1OctetString.getInstance(tagged, false).getOctets(), ASN1Integer.getInstance(s.getObjectAt(1)).getValue().intValue());
					}
				}
				else if (s.size() == 3)
				{
					ASN1TaggedObject tagged1 = ASN1TaggedObject.getInstance(s.getObjectAt(0));
					ASN1TaggedObject tagged2 = ASN1TaggedObject.getInstance(s.getObjectAt(1));

					this.currentSpec = new IESParameterSpec(ASN1OctetString.getInstance(tagged1, false).getOctets(), ASN1OctetString.getInstance(tagged2, false).getOctets(), ASN1Integer.getInstance(s.getObjectAt(2)).getValue().intValue());
				}
				else if (s.size() == 4)
				{
					ASN1TaggedObject tagged1 = ASN1TaggedObject.getInstance(s.getObjectAt(0));
					ASN1TaggedObject tagged2 = ASN1TaggedObject.getInstance(s.getObjectAt(1));
					ASN1Sequence cipherDet = ASN1Sequence.getInstance(s.getObjectAt(3));

					this.currentSpec = new IESParameterSpec(ASN1OctetString.getInstance(tagged1, false).getOctets(), ASN1OctetString.getInstance(tagged2, false).getOctets(), ASN1Integer.getInstance(s.getObjectAt(2)).getValue().intValue(), ASN1Integer.getInstance(cipherDet.getObjectAt(0)).getValue().intValue(), ASN1OctetString.getInstance(cipherDet.getObjectAt(1)).getOctets());
				}
			}
			catch (ClassCastException)
			{
				throw new IOException("Not a valid IES Parameter encoding.");
			}
			catch (ArrayIndexOutOfBoundsException)
			{
				throw new IOException("Not a valid IES Parameter encoding.");
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
			return "IES Parameters";
		}
	}

}