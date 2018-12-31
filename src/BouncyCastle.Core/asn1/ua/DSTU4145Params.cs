using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.ua
{
	
	public class DSTU4145Params : ASN1Object
	{
		private static readonly byte[] DEFAULT_DKE = new byte[] {unchecked(0xa9), unchecked(0xd6), unchecked(0xeb), 0x45, unchecked(0xf1), 0x3c, 0x70, unchecked(0x82), unchecked(0x80), unchecked(0xc4), unchecked(0x96), 0x7b, 0x23, 0x1f, 0x5e, unchecked(0xad), unchecked(0xf6), 0x58, unchecked(0xeb), unchecked(0xa4), unchecked(0xc0), 0x37, 0x29, 0x1d, 0x38, unchecked(0xd9), 0x6b, unchecked(0xf0), 0x25, unchecked(0xca), 0x4e, 0x17, unchecked(0xf8), unchecked(0xe9), 0x72, 0x0d, unchecked(0xc6), 0x15, unchecked(0xb4), 0x3a, 0x28, unchecked(0x97), 0x5f, 0x0b, unchecked(0xc1), unchecked(0xde), unchecked(0xa3), 0x64, 0x38, unchecked(0xb5), 0x64, unchecked(0xea), 0x2c, 0x17, unchecked(0x9f), unchecked(0xd0), 0x12, 0x3e, 0x6d, unchecked(0xb8), unchecked(0xfa), unchecked(0xc5), 0x79, 0x04};


		private ASN1ObjectIdentifier namedCurve;
		private DSTU4145ECBinary ecbinary;
		private byte[] dke = DEFAULT_DKE;

		public DSTU4145Params(ASN1ObjectIdentifier namedCurve)
		{
			this.namedCurve = namedCurve;
		}

		public DSTU4145Params(ASN1ObjectIdentifier namedCurve, byte[] dke)
		{
			this.namedCurve = namedCurve;
			this.dke = Arrays.clone(dke);
		}

		public DSTU4145Params(DSTU4145ECBinary ecbinary)
		{
			this.ecbinary = ecbinary;
		}

		public virtual bool isNamedCurve()
		{
			return namedCurve != null;
		}

		public virtual DSTU4145ECBinary getECBinary()
		{
			return ecbinary;
		}

		public virtual byte[] getDKE()
		{
			return Arrays.clone(dke);
		}

		public static byte[] getDefaultDKE()
		{
			return Arrays.clone(DEFAULT_DKE);
		}

		public virtual ASN1ObjectIdentifier getNamedCurve()
		{
			return namedCurve;
		}

		public static DSTU4145Params getInstance(object obj)
		{
			if (obj is DSTU4145Params)
			{
				return (DSTU4145Params)obj;
			}

			if (obj != null)
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(obj);
				DSTU4145Params @params;

				if (seq.getObjectAt(0) is ASN1ObjectIdentifier)
				{
					@params = new DSTU4145Params(ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)));
				}
				else
				{
					@params = new DSTU4145Params(DSTU4145ECBinary.getInstance(seq.getObjectAt(0)));
				}

				if (seq.size() == 2)
				{
					@params.dke = ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets();
					if (@params.dke.Length != DSTU4145Params.DEFAULT_DKE.Length)
					{
						throw new IllegalArgumentException("object parse error");
					}
				}

				return @params;
			}

			throw new IllegalArgumentException("object parse error");
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (namedCurve != null)
			{
				v.add(namedCurve);
			}
			else
			{
				v.add(ecbinary);
			}

			if (!Arrays.areEqual(dke, DEFAULT_DKE))
			{
				v.add(new DEROctetString(dke));
			}

			return new DERSequence(v);
		}
	}

}