using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.isismtt.x509
{

	
	/// <summary>
	/// An Admissions structure.
	/// <pre>
	///            Admissions ::= SEQUENCE
	///            {
	///              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
	///              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
	///              professionInfos SEQUENCE OF ProfessionInfo
	///            }
	/// </pre>
	/// </summary>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax </seealso>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.ProfessionInfo </seealso>
	/// <seealso cref= org.bouncycastle.asn1.isismtt.x509.NamingAuthority </seealso>
	public class Admissions : ASN1Object
	{

		private GeneralName admissionAuthority;

		private NamingAuthority namingAuthority;

		private ASN1Sequence professionInfos;

		public static Admissions getInstance(object obj)
		{
			if (obj == null || obj is Admissions)
			{
				return (Admissions)obj;
			}

			if (obj is ASN1Sequence)
			{
				return new Admissions((ASN1Sequence)obj);
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Constructor from ASN1Sequence.
		/// <para>
		/// The sequence is of type ProcurationSyntax:
		/// <pre>
		///            Admissions ::= SEQUENCE
		///            {
		///              admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		///              namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		///              professionInfos SEQUENCE OF ProfessionInfo
		///            }
		/// </pre>
		/// </para> </summary>
		/// <param name="seq"> The ASN.1 sequence. </param>
		private Admissions(ASN1Sequence seq)
		{
			if (seq.size() > 3)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}
			Enumeration e = seq.getObjects();

			ASN1Encodable o = (ASN1Encodable)e.nextElement();
			if (o is ASN1TaggedObject)
			{
				switch (((ASN1TaggedObject)o).getTagNo())
				{
				case 0:
					admissionAuthority = GeneralName.getInstance((ASN1TaggedObject)o, true);
					break;
				case 1:
					namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
					break;
				default:
					throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject)o).getTagNo());
				}
				o = (ASN1Encodable)e.nextElement();
			}
			if (o is ASN1TaggedObject)
			{
				switch (((ASN1TaggedObject)o).getTagNo())
				{
				case 1:
					namingAuthority = NamingAuthority.getInstance((ASN1TaggedObject)o, true);
					break;
				default:
					throw new IllegalArgumentException("Bad tag number: " + ((ASN1TaggedObject)o).getTagNo());
				}
				o = (ASN1Encodable)e.nextElement();
			}
			professionInfos = ASN1Sequence.getInstance(o);
			if (e.hasMoreElements())
			{
				throw new IllegalArgumentException("Bad object encountered: " + e.nextElement().GetType());
			}
		}

		/// <summary>
		/// Constructor from a given details.
		/// <para>
		/// Parameter <code>professionInfos</code> is mandatory.
		/// 
		/// </para>
		/// </summary>
		/// <param name="admissionAuthority"> The admission authority. </param>
		/// <param name="namingAuthority">    The naming authority. </param>
		/// <param name="professionInfos">    The profession infos. </param>
		public Admissions(GeneralName admissionAuthority, NamingAuthority namingAuthority, ProfessionInfo[] professionInfos)
		{
			this.admissionAuthority = admissionAuthority;
			this.namingAuthority = namingAuthority;
			this.professionInfos = new DERSequence(professionInfos);
		}

		public virtual GeneralName getAdmissionAuthority()
		{
			return admissionAuthority;
		}

		public virtual NamingAuthority getNamingAuthority()
		{
			return namingAuthority;
		}

		public virtual ProfessionInfo[] getProfessionInfos()
		{
			ProfessionInfo[] infos = new ProfessionInfo[professionInfos.size()];
			int count = 0;
			for (Enumeration e = professionInfos.getObjects(); e.hasMoreElements();)
			{
				infos[count++] = ProfessionInfo.getInstance(e.nextElement());
			}
			return infos;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <para>
		/// Returns:
		/// <pre>
		///       Admissions ::= SEQUENCE
		///       {
		///         admissionAuthority [0] EXPLICIT GeneralName OPTIONAL
		///         namingAuthority [1] EXPLICIT NamingAuthority OPTIONAL
		///         professionInfos SEQUENCE OF ProfessionInfo
		///       }
		/// </pre>
		/// 
		/// </para>
		/// </summary>
		/// <returns> an ASN1Primitive </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector vec = new ASN1EncodableVector();

			if (admissionAuthority != null)
			{
				vec.add(new DERTaggedObject(true, 0, admissionAuthority));
			}
			if (namingAuthority != null)
			{
				vec.add(new DERTaggedObject(true, 1, namingAuthority));
			}
			vec.add(professionInfos);

			return new DERSequence(vec);
		}
	}

}