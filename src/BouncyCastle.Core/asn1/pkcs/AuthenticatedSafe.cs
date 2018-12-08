using org.bouncycastle.Port;

namespace org.bouncycastle.asn1.pkcs
{

	public class AuthenticatedSafe : ASN1Object
	{
		private ContentInfo[] info;
		private bool isBer = true;

		private AuthenticatedSafe(ASN1Sequence seq)
		{
			info = new ContentInfo[seq.size()];

			for (int i = 0; i != info.Length; i++)
			{
				info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
			}

			isBer = seq is BERSequence;
		}

		public static AuthenticatedSafe getInstance(object o)
		{
			if (o is AuthenticatedSafe)
			{
				return (AuthenticatedSafe)o;
			}

			if (o != null)
			{
				return new AuthenticatedSafe(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public AuthenticatedSafe(ContentInfo[] info)
		{
			this.info = copy(info);
		}

		public virtual ContentInfo[] getContentInfo()
		{
			return copy(info);
		}

		private ContentInfo[] copy(ContentInfo[] infos)
		{
			ContentInfo[] tmp = new ContentInfo[infos.Length];

			JavaSystem.arraycopy(infos, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			for (int i = 0; i != info.Length; i++)
			{
				v.add(info[i]);
			}

			if (isBer)
			{
				return new BERSequence(v);
			}
			else
			{
				return new DLSequence(v);
			}
		}
	}

}