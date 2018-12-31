using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.bc
{
		
	/// <summary>
	/// <pre>
	///     EncryptedPrivateKeyObjectData ::= SEQUENCE {
	///         encryptedPrivateKeyInfo EncryptedPrivateKeyInfo,
	///         certificates SEQUENCE OF Certificate
	///     }
	/// </pre>
	/// </summary>
	public class EncryptedPrivateKeyData : ASN1Object
	{
		private readonly EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
		private readonly Certificate[] certificateChain;

		public EncryptedPrivateKeyData(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] certificateChain)
		{
			this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
			this.certificateChain = new Certificate[certificateChain.Length];
			JavaSystem.arraycopy(certificateChain, 0, this.certificateChain, 0, certificateChain.Length);
		}

		private EncryptedPrivateKeyData(ASN1Sequence seq)
		{
			encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(seq.getObjectAt(0));
			ASN1Sequence certSeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
			certificateChain = new Certificate[certSeq.size()];
			for (int i = 0; i != certificateChain.Length; i++)
			{
				certificateChain[i] = Certificate.getInstance(certSeq.getObjectAt(i));
			}
		}

		public static EncryptedPrivateKeyData getInstance(object o)
		{
			if (o is EncryptedPrivateKeyData)
			{
				return (EncryptedPrivateKeyData)o;
			}
			else if (o != null)
			{
				return new EncryptedPrivateKeyData(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual Certificate[] getCertificateChain()
		{
			Certificate[] tmp = new Certificate[certificateChain.Length];

			JavaSystem.arraycopy(certificateChain, 0, tmp, 0, certificateChain.Length);

			return tmp;
		}

		public virtual EncryptedPrivateKeyInfo getEncryptedPrivateKeyInfo()
		{
			return encryptedPrivateKeyInfo;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(encryptedPrivateKeyInfo);
			v.add(new DERSequence(certificateChain));

			return new DERSequence(v);
		}
	}

}