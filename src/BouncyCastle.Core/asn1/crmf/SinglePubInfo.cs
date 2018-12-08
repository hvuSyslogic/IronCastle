namespace org.bouncycastle.asn1.crmf
{
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;

	/// <summary>
	/// <pre>
	/// SinglePubInfo ::= SEQUENCE {
	///        pubMethod    INTEGER {
	///           dontCare    (0),
	///           x500        (1),
	///           web         (2),
	///           ldap        (3) },
	///       pubLocation  GeneralName OPTIONAL }
	/// </pre>
	/// </summary>
	public class SinglePubInfo : ASN1Object
	{
		public static readonly ASN1Integer dontCare = new ASN1Integer(0);
		public static readonly ASN1Integer x500 = new ASN1Integer(1);
		public static readonly ASN1Integer web = new ASN1Integer(2);
		public static readonly ASN1Integer ldap = new ASN1Integer(3);

		private ASN1Integer pubMethod;
		private GeneralName pubLocation;

		private SinglePubInfo(ASN1Sequence seq)
		{
			pubMethod = ASN1Integer.getInstance(seq.getObjectAt(0));

			if (seq.size() == 2)
			{
				pubLocation = GeneralName.getInstance(seq.getObjectAt(1));
			}
		}

		public static SinglePubInfo getInstance(object o)
		{
			if (o is SinglePubInfo)
			{
				return (SinglePubInfo)o;
			}

			if (o != null)
			{
				return new SinglePubInfo(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public SinglePubInfo(ASN1Integer pubMethod, GeneralName pubLocation)
		{
			this.pubMethod = pubMethod;
			this.pubLocation = pubLocation;
		}

		public virtual ASN1Integer getPubMethod()
		{
			return pubMethod;
		}

		public virtual GeneralName getPubLocation()
		{
			return pubLocation;
		}

		/// <summary>
		/// Return the primitive representation of SinglePubInfo.
		/// </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(pubMethod);

			if (pubLocation != null)
			{
				v.add(pubLocation);
			}

			return new DERSequence(v);
		}
	}

}