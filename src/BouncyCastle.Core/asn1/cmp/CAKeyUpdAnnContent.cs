namespace org.bouncycastle.asn1.cmp
{

	public class CAKeyUpdAnnContent : ASN1Object
	{
		private CMPCertificate oldWithNew;
		private CMPCertificate newWithOld;
		private CMPCertificate newWithNew;

		private CAKeyUpdAnnContent(ASN1Sequence seq)
		{
			oldWithNew = CMPCertificate.getInstance(seq.getObjectAt(0));
			newWithOld = CMPCertificate.getInstance(seq.getObjectAt(1));
			newWithNew = CMPCertificate.getInstance(seq.getObjectAt(2));
		}

		public static CAKeyUpdAnnContent getInstance(object o)
		{
			if (o is CAKeyUpdAnnContent)
			{
				return (CAKeyUpdAnnContent)o;
			}

			if (o != null)
			{
				return new CAKeyUpdAnnContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CAKeyUpdAnnContent(CMPCertificate oldWithNew, CMPCertificate newWithOld, CMPCertificate newWithNew)
		{
			this.oldWithNew = oldWithNew;
			this.newWithOld = newWithOld;
			this.newWithNew = newWithNew;
		}

		public virtual CMPCertificate getOldWithNew()
		{
			return oldWithNew;
		}

		public virtual CMPCertificate getNewWithOld()
		{
			return newWithOld;
		}

		public virtual CMPCertificate getNewWithNew()
		{
			return newWithNew;
		}

		/// <summary>
		/// <pre>
		/// CAKeyUpdAnnContent ::= SEQUENCE {
		///                             oldWithNew   CMPCertificate, -- old pub signed with new priv
		///                             newWithOld   CMPCertificate, -- new pub signed with old priv
		///                             newWithNew   CMPCertificate  -- new pub signed with new priv
		///  }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(oldWithNew);
			v.add(newWithOld);
			v.add(newWithNew);

			return new DERSequence(v);
		}
	}

}