using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{

	public class GeneralNamesBuilder
	{
		private Vector names = new Vector();

		public virtual GeneralNamesBuilder addNames(GeneralNames names)
		{
			GeneralName[] n = names.getNames();

			for (int i = 0; i != n.Length; i++)
			{
				this.names.addElement(n[i]);
			}

			return this;
		}

		public virtual GeneralNamesBuilder addName(GeneralName name)
		{
			names.addElement(name);

			return this;
		}

		public virtual GeneralNames build()
		{
			GeneralName[] tmp = new GeneralName[names.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = (GeneralName)names.elementAt(i);
			}

			return new GeneralNames(tmp);
		}
	}

}