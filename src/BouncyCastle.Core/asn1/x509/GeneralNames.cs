using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.x509
{
	
	public class GeneralNames : ASN1Object
	{
		private readonly GeneralName[] names;

		public static GeneralNames getInstance(object obj)
		{
			if (obj is GeneralNames)
			{
				return (GeneralNames)obj;
			}

			if (obj != null)
			{
				return new GeneralNames(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static GeneralNames getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public static GeneralNames fromExtensions(Extensions extensions, ASN1ObjectIdentifier extOID)
		{
			return GeneralNames.getInstance(extensions.getExtensionParsedValue(extOID));
		}

		/// <summary>
		/// Construct a GeneralNames object containing one GeneralName.
		/// </summary>
		/// <param name="name"> the name to be contained. </param>
		public GeneralNames(GeneralName name)
		{
			this.names = new GeneralName[] {name};
		}


		public GeneralNames(GeneralName[] names)
		{
			this.names = copy(names);
		}

		private GeneralNames(ASN1Sequence seq)
		{
			this.names = new GeneralName[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				names[i] = GeneralName.getInstance(seq.getObjectAt(i));
			}
		}

		public virtual GeneralName[] getNames()
		{
			return copy(names);
		}

		private GeneralName[] copy(GeneralName[] nms)
		{
			GeneralName[] tmp = new GeneralName[nms.Length];

			JavaSystem.arraycopy(nms, 0, tmp, 0, tmp.Length);

			return tmp;
		}

		/// <summary>
		/// Produce an object suitable for an ASN1OutputStream.
		/// <pre>
		/// GeneralNames ::= SEQUENCE SIZE {1..MAX} OF GeneralName
		/// </pre>
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(names);
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string sep = Strings.lineSeparator();

			buf.append("GeneralNames:");
			buf.append(sep);

			for (int i = 0; i != names.Length; i++)
			{
				buf.append("    ");
				buf.append(names[i]);
				buf.append(sep);
			}
			return buf.ToString();
		}
	}

}