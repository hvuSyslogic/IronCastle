using org.bouncycastle.asn1.x500;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{

	
	/// <summary>
	/// Professions, specializations, disciplines, fields of activity, etc.
	/// 
	/// <pre>
	///               ProfessionInfo ::= SEQUENCE 
	///               {
	///                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
	///                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
	///                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
	///                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
	///                 addProfessionInfo OCTET STRING OPTIONAL 
	///               }
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax </seealso>
	public class ProfessionInfo : ASN1Object
	{

		/// <summary>
		/// Rechtsanw�ltin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Rechtsanwltin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".1");

		/// <summary>
		/// Rechtsanwalt
		/// </summary>
		public static readonly ASN1ObjectIdentifier Rechtsanwalt = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".2");

		/// <summary>
		/// Rechtsbeistand
		/// </summary>
		public static readonly ASN1ObjectIdentifier Rechtsbeistand = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".3");

		/// <summary>
		/// Steuerberaterin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Steuerberaterin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".4");

		/// <summary>
		/// Steuerberater
		/// </summary>
		public static readonly ASN1ObjectIdentifier Steuerberater = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".5");

		/// <summary>
		/// Steuerbevollm�chtigte
		/// </summary>
		public static readonly ASN1ObjectIdentifier Steuerbevollmchtigte = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".6");

		/// <summary>
		/// Steuerbevollm�chtigter
		/// </summary>
		public static readonly ASN1ObjectIdentifier Steuerbevollmchtigter = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".7");

		/// <summary>
		/// Notarin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notarin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".8");

		/// <summary>
		/// Notar
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notar = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".9");

		/// <summary>
		/// Notarvertreterin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notarvertreterin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".10");

		/// <summary>
		/// Notarvertreter
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notarvertreter = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".11");

		/// <summary>
		/// Notariatsverwalterin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notariatsverwalterin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".12");

		/// <summary>
		/// Notariatsverwalter
		/// </summary>
		public static readonly ASN1ObjectIdentifier Notariatsverwalter = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".13");

		/// <summary>
		/// Wirtschaftspr�ferin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Wirtschaftsprferin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".14");

		/// <summary>
		/// Wirtschaftspr�fer
		/// </summary>
		public static readonly ASN1ObjectIdentifier Wirtschaftsprfer = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".15");

		/// <summary>
		/// Vereidigte Buchpr�ferin
		/// </summary>
		public static readonly ASN1ObjectIdentifier VereidigteBuchprferin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".16");

		/// <summary>
		/// Vereidigter Buchpr�fer
		/// </summary>
		public static readonly ASN1ObjectIdentifier VereidigterBuchprfer = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".17");

		/// <summary>
		/// Patentanw�ltin
		/// </summary>
		public static readonly ASN1ObjectIdentifier Patentanwltin = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".18");

		/// <summary>
		/// Patentanwalt
		/// </summary>
		public static readonly ASN1ObjectIdentifier Patentanwalt = new ASN1ObjectIdentifier(NamingAuthority.id_isismtt_at_namingAuthorities_RechtWirtschaftSteuern + ".19");

		private NamingAuthority namingAuthority;

		private ASN1Sequence professionItems;

		private ASN1Sequence professionOIDs;

		private string registrationNumber;

		private ASN1OctetString addProfessionInfo;

		public static ProfessionInfo getInstance(object obj)
		{
			if (obj == null || obj is ProfessionInfo)
			{
				return (ProfessionInfo)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new ProfessionInfo((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <pre>
		///               ProfessionInfo ::= SEQUENCE
		///               {
		///                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		///                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		///                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		///                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		///                 addProfessionInfo OCTET STRING OPTIONAL
		///               }
		/// </pre>
		/// </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private ProfessionInfo(ASN1Sequence seq)
		{
			if (seq.size() > 5)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			Enumeration e = seq.getObjects();

			ASN1Encodable o = (ASN1Encodable)e.nextElement();

			if (o is ASN1TaggedObject)
			{
				if (((ASN1TaggedObject)o).getTagNo() != 0)
				{
					throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject)o).getTagNo());
				}
				namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
				o = (ASN1Encodable)e.nextElement();
			}

			professionItems = ASN1Sequence.getInstance(o);

			if (e.hasMoreElements())
			{
				o = (ASN1Encodable)e.nextElement();
				if (o is ASN1Sequence)
				{
					professionOIDs = ASN1Sequence.getInstance(o);
				}
				else if (o is DERPrintableString)
				{
					registrationNumber = DERPrintableString.getInstance(o).getString();
				}
				else if (o is ASN1OctetString)
				{
					addProfessionInfo = ASN1OctetString.getInstance(o);
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}
			}
			if (e.hasMoreElements())
			{
				o = (ASN1Encodable)e.nextElement();
				if (o is DERPrintableString)
				{
					registrationNumber = DERPrintableString.getInstance(o).getString();
				}
				else if (o is DEROctetString)
				{
					addProfessionInfo = (DEROctetString)o;
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}
			}
			if (e.hasMoreElements())
			{
				o = (ASN1Encodable)e.nextElement();
				if (o is DEROctetString)
				{
					addProfessionInfo = (DEROctetString)o;
				}
				else
				{
					throw new IllegalArgumentException("Bad object encountered: " + o.GetType());
				}
			}

		}

		/// <summary>
		/// Constructor from given details.
		/// <para>
		/// <code>professionItems</code> is mandatory, all other parameters are
		/// optional.
		/// 
		/// </para>
		/// </summary>
		/// <param name="namingAuthority">    The naming authority. </param>
		/// <param name="professionItems">    Directory strings of the profession. </param>
		/// <param name="professionOIDs">     DERObjectIdentfier objects for the
		///                           profession. </param>
		/// <param name="registrationNumber"> Registration number. </param>
		/// <param name="addProfessionInfo">  Additional infos in encoded form. </param>
		public ProfessionInfo(NamingAuthority namingAuthority, DirectoryString[] professionItems, ASN1ObjectIdentifier[] professionOIDs, string registrationNumber, ASN1OctetString addProfessionInfo)
		{
			this.namingAuthority = namingAuthority;
			ASN1EncodableVector v = new ASN1EncodableVector();
			for (int i = 0; i != professionItems.Length; i++)
			{
				v.add(professionItems[i]);
			}
			this.professionItems = new DERSequence(v);
			if (professionOIDs != null)
			{
				v = new ASN1EncodableVector();
				for (int i = 0; i != professionOIDs.Length; i++)
				{
					v.add(professionOIDs[i]);
				}
				this.professionOIDs = new DERSequence(v);
			}
			this.registrationNumber = registrationNumber;
			this.addProfessionInfo = addProfessionInfo;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///               ProfessionInfo ::= SEQUENCE
		///               {
		///                 namingAuthority [0] EXPLICIT NamingAuthority OPTIONAL,
		///                 professionItems SEQUENCE OF DirectoryString (SIZE(1..128)),
		///                 professionOIDs SEQUENCE OF OBJECT IDENTIFIER OPTIONAL,
		///                 registrationNumber PrintableString(SIZE(1..128)) OPTIONAL,
		///                 addProfessionInfo OCTET STRING OPTIONAL
		///               }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> a DERObject </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();
			if (namingAuthority != null)
			{
				vec.add(new DERTaggedObject(true, 0, namingAuthority));
			}
			vec.add(professionItems);
			if (professionOIDs != null)
			{
				vec.add(professionOIDs);
			}
			if (!string.ReferenceEquals(registrationNumber, null))
			{
				vec.add(new DERPrintableString(registrationNumber, true));
			}
			if (addProfessionInfo != null)
			{
				vec.add(addProfessionInfo);
			}
			return new DERSequence(vec);
		}

		/// <returns> Returns the addProfessionInfo. </returns>
		public virtual ASN1OctetString getAddProfessionInfo()
		{
			return addProfessionInfo;
		}

		/// <returns> Returns the namingAuthority. </returns>
		public virtual NamingAuthority getNamingAuthority()
		{
			return namingAuthority;
		}

		/// <returns> Returns the professionItems. </returns>
		public virtual DirectoryString[] getProfessionItems()
		{
			DirectoryString[] items = new DirectoryString[professionItems.size()];
			int count = 0;
			for (Enumeration e = professionItems.getObjects(); e.hasMoreElements();)
			{
				items[count++] = DirectoryString.getInstance(e.nextElement());
			}
			return items;
		}

		/// <returns> Returns the professionOIDs. </returns>
		public virtual ASN1ObjectIdentifier[] getProfessionOIDs()
		{
			if (professionOIDs == null)
			{
				return new ASN1ObjectIdentifier[0];
			}
			ASN1ObjectIdentifier[] oids = new ASN1ObjectIdentifier[professionOIDs.size()];
			int count = 0;
			for (Enumeration e = professionOIDs.getObjects(); e.hasMoreElements();)
			{
				oids[count++] = ASN1ObjectIdentifier.getInstance(e.nextElement());
			}
			return oids;
		}

		/// <returns> Returns the registrationNumber. </returns>
		public virtual string getRegistrationNumber()
		{
			return registrationNumber;
		}
	}

}