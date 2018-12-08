using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.x509
{


	public class NameConstraints : ASN1Object
	{
		private GeneralSubtree[] permitted, excluded;

		public static NameConstraints getInstance(object obj)
		{
			if (obj is NameConstraints)
			{
				return (NameConstraints)obj;
			}
			if (obj != null)
			{
				return new NameConstraints(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private NameConstraints(ASN1Sequence seq)
		{
			Enumeration e = seq.getObjects();
			while (e.hasMoreElements())
			{
				ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
				switch (o.getTagNo())
				{
				case 0:
					permitted = createArray(ASN1Sequence.getInstance(o, false));
					break;
				case 1:
					excluded = createArray(ASN1Sequence.getInstance(o, false));
					break;
				default:
					throw new IllegalArgumentException("Unknown tag encountered: " + o.getTagNo());
				}
			}
		}

		/// <summary>
		/// Constructor from a given details.
		/// 
		/// <para>
		/// permitted and excluded are arrays of GeneralSubtree objects.
		/// 
		/// </para>
		/// </summary>
		/// <param name="permitted">
		///            Permitted subtrees </param>
		/// <param name="excluded">
		///            Excludes subtrees </param>
		public NameConstraints(GeneralSubtree[] permitted, GeneralSubtree[] excluded)
		{
			this.permitted = cloneSubtree(permitted);
			this.excluded = cloneSubtree(excluded);
		}

		private GeneralSubtree[] createArray(ASN1Sequence subtree)
		{
			GeneralSubtree[] ar = new GeneralSubtree[subtree.size()];

			for (int i = 0; i != ar.Length; i++)
			{
				ar[i] = GeneralSubtree.getInstance(subtree.getObjectAt(i));
			}

			return ar;
		}

		public virtual GeneralSubtree[] getPermittedSubtrees()
		{
			return cloneSubtree(permitted);
		}

		public virtual GeneralSubtree[] getExcludedSubtrees()
		{
			return cloneSubtree(excluded);
		}

		/*
		 * NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees
		 * OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }
		 */
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (permitted != null)
			{
				v.add(new DERTaggedObject(false, 0, new DERSequence(permitted)));
			}

			if (excluded != null)
			{
				v.add(new DERTaggedObject(false, 1, new DERSequence(excluded)));
			}

			return new DERSequence(v);
		}

		private static GeneralSubtree[] cloneSubtree(GeneralSubtree[] subtrees)
		{
			if (subtrees != null)
			{
				GeneralSubtree[] rv = new GeneralSubtree[subtrees.Length];

				JavaSystem.arraycopy(subtrees, 0, rv, 0, rv.Length);

				return rv;
			}

			return null;
		}
	}

}