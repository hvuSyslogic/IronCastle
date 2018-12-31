using org.bouncycastle.asn1.crmf;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmp
{
		
	public class OOBCertHash : ASN1Object
	{
		private AlgorithmIdentifier hashAlg;
		private CertId certId;
		private DERBitString hashVal;

		private OOBCertHash(ASN1Sequence seq)
		{
			int index = seq.size() - 1;

			hashVal = DERBitString.getInstance(seq.getObjectAt(index--));

			for (int i = index; i >= 0; i--)
			{
				ASN1TaggedObject tObj = (ASN1TaggedObject)seq.getObjectAt(i);

				if (tObj.getTagNo() == 0)
				{
					hashAlg = AlgorithmIdentifier.getInstance(tObj, true);
				}
				else
				{
					certId = CertId.getInstance(tObj, true);
				}
			}

		}

		public static OOBCertHash getInstance(object o)
		{
			if (o is OOBCertHash)
			{
				return (OOBCertHash)o;
			}

			if (o != null)
			{
				return new OOBCertHash(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal) : this(hashAlg, certId, new DERBitString(hashVal))
		{
		}

		public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, DERBitString hashVal)
		{
			this.hashAlg = hashAlg;
			this.certId = certId;
			this.hashVal = hashVal;
		}

		public virtual AlgorithmIdentifier getHashAlg()
		{
			return hashAlg;
		}

		public virtual CertId getCertId()
		{
			return certId;
		}

		public virtual DERBitString getHashVal()
		{
			return hashVal;
		}

		/// <summary>
		/// <pre>
		/// OOBCertHash ::= SEQUENCE {
		///                      hashAlg     [0] AlgorithmIdentifier     OPTIONAL,
		///                      certId      [1] CertId                  OPTIONAL,
		///                      hashVal         BIT STRING
		///                      -- hashVal is calculated over the DER encoding of the
		///                      -- self-signed certificate with the identifier certID.
		///       }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			addOptional(v, 0, hashAlg);
			addOptional(v, 1, certId);

			v.add(hashVal);

			return new DERSequence(v);
		}

		private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(new DERTaggedObject(true, tagNo, obj));
			}
		}
	}

}