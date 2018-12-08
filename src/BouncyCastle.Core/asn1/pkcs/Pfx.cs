using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.pkcs
{


	/// <summary>
	/// the infamous Pfx from PKCS12
	/// </summary>
	public class Pfx : ASN1Object, PKCSObjectIdentifiers
	{
		private ContentInfo contentInfo;
		private MacData macData = null;

		private Pfx(ASN1Sequence seq)
		{
			BigInteger version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
			if (version.intValue() != 3)
			{
				throw new IllegalArgumentException("wrong version for PFX PDU");
			}

			contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));

			if (seq.size() == 3)
			{
				macData = MacData.getInstance(seq.getObjectAt(2));
			}
		}

		public static Pfx getInstance(object obj)
		{
			if (obj is Pfx)
			{
				return (Pfx)obj;
			}

			if (obj != null)
			{
				return new Pfx(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public Pfx(ContentInfo contentInfo, MacData macData)
		{
			this.contentInfo = contentInfo;
			this.macData = macData;
		}

		public virtual ContentInfo getAuthSafe()
		{
			return contentInfo;
		}

		public virtual MacData getMacData()
		{
			return macData;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(new ASN1Integer(3));
			v.add(contentInfo);

			if (macData != null)
			{
				v.add(macData);
			}

			return new BERSequence(v);
		}
	}

}