using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Mutable class for building ASN.1 constructed objects such as SETs or SEQUENCEs.
	/// </summary>
	public class ASN1EncodableVector
	{
		private readonly Vector v = new Vector();

		/// <summary>
		/// Base constructor.
		/// </summary>
		public ASN1EncodableVector()
		{
		}

		/// <summary>
		/// Add an encodable to the vector.
		/// </summary>
		/// <param name="obj"> the encodable to add. </param>
		public virtual void add(ASN1Encodable obj)
		{
			v.addElement(obj);
		}

		/// <summary>
		/// Add the contents of another vector.
		/// </summary>
		/// <param name="other"> the vector to add. </param>
		public virtual void addAll(ASN1EncodableVector other)
		{
			for (Enumeration en = other.v.elements(); en.hasMoreElements();)
			{
				v.addElement(en.nextElement());
			}
		}

		/// <summary>
		/// Return the object at position i in this vector.
		/// </summary>
		/// <param name="i"> the index of the object of interest. </param>
		/// <returns> the object at position i. </returns>
		public virtual ASN1Encodable get(int i)
		{
			return (ASN1Encodable)v.elementAt(i);
		}

		/// <summary>
		/// Return the size of the vector.
		/// </summary>
		/// <returns> the object count in the vector. </returns>
		public virtual int size()
		{
			return v.size();
		}
	}

}