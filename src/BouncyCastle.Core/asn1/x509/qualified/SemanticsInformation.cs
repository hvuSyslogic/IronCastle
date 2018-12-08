using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509.qualified
{


	/// <summary>
	/// The SemanticsInformation object.
	/// <pre>
	///       SemanticsInformation ::= SEQUENCE {
	///         semanticsIdentifier        OBJECT IDENTIFIER   OPTIONAL,
	///         nameRegistrationAuthorities NameRegistrationAuthorities
	///                                                         OPTIONAL }
	///         (WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
	///          WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
	/// 
	///     NameRegistrationAuthorities ::=  SEQUENCE SIZE (1..MAX) OF
	///         GeneralName
	/// </pre>
	/// </summary>
	public class SemanticsInformation : ASN1Object
	{
		private ASN1ObjectIdentifier semanticsIdentifier;
		private GeneralName[] nameRegistrationAuthorities;

		public static SemanticsInformation getInstance(object obj)
		{
			if (obj is SemanticsInformation)
			{
				return (SemanticsInformation)obj;
			}

			if (obj != null)
			{
				return new SemanticsInformation(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private SemanticsInformation(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();
			if (seq.size() < 1)
			{
				 throw new IllegalArgumentException("no objects in SemanticsInformation");
			}

			object @object = e.nextElement();
			if (@object is ASN1ObjectIdentifier)
			{
				semanticsIdentifier = ASN1ObjectIdentifier.getInstance(@object);
				if (e.hasMoreElements())
				{
					@object = e.nextElement();
				}
				else
				{
					@object = null;
				}
			}

			if (@object != null)
			{
				ASN1Sequence generalNameSeq = ASN1Sequence.getInstance(@object);
				nameRegistrationAuthorities = new GeneralName[generalNameSeq.size()];
				for (int i = 0; i < generalNameSeq.size(); i++)
				{
					nameRegistrationAuthorities[i] = GeneralName.getInstance(generalNameSeq.getObjectAt(i));
				}
			}
		}

		public SemanticsInformation(ASN1ObjectIdentifier semanticsIdentifier, GeneralName[] generalNames)
		{
			this.semanticsIdentifier = semanticsIdentifier;
			this.nameRegistrationAuthorities = cloneNames(generalNames);
		}

		public SemanticsInformation(ASN1ObjectIdentifier semanticsIdentifier)
		{
			this.semanticsIdentifier = semanticsIdentifier;
			this.nameRegistrationAuthorities = null;
		}

		public SemanticsInformation(GeneralName[] generalNames)
		{
			this.semanticsIdentifier = null;
			this.nameRegistrationAuthorities = cloneNames(generalNames);
		}

		public virtual ASN1ObjectIdentifier getSemanticsIdentifier()
		{
			return semanticsIdentifier;
		}

		public virtual GeneralName[] getNameRegistrationAuthorities()
		{
			return cloneNames(nameRegistrationAuthorities);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();

			if (this.semanticsIdentifier != null)
			{
				seq.add(semanticsIdentifier);
			}
			if (this.nameRegistrationAuthorities != null)
			{
				ASN1EncodableVector seqname = new ASN1EncodableVector();
				for (int i = 0; i < nameRegistrationAuthorities.Length; i++)
				{
					seqname.add(nameRegistrationAuthorities[i]);
				}
				seq.add(new DERSequence(seqname));
			}

			return new DERSequence(seq);
		}

		private static GeneralName[] cloneNames(GeneralName[] names)
		{
			if (names != null)
			{
				GeneralName[] tmp = new GeneralName[names.Length];

				JavaSystem.arraycopy(names, 0, tmp, 0, names.Length);

				return tmp;
			}
			return null;
		}
	}

}