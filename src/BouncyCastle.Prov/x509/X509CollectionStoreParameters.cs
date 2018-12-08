namespace org.bouncycastle.x509
{

	/// <summary>
	/// This class contains a collection for collection based <code>X509Store</code>s.
	/// </summary>
	/// <seealso cref= org.bouncycastle.x509.X509Store
	///  </seealso>
	public class X509CollectionStoreParameters : X509StoreParameters
	{
		private Collection collection;

		/// <summary>
		/// Constructor.
		/// <para>
		/// The collection is copied.
		/// </para>
		/// </summary>
		/// <param name="collection">
		///            The collection containing X.509 object types. </param>
		/// <exception cref="NullPointerException"> if <code>collection</code> is <code>null</code>. </exception>
		public X509CollectionStoreParameters(Collection collection)
		{
			if (collection == null)
			{
				throw new NullPointerException("collection cannot be null");
			}
			this.collection = collection;
		}

		/// <summary>
		/// Returns a shallow clone. The returned contents are not copied, so adding
		/// or removing objects will effect this.
		/// </summary>
		/// <returns> a shallow clone. </returns>
		public virtual object clone()
		{
			return new X509CollectionStoreParameters(collection);
		}

		/// <summary>
		/// Returns a copy of the <code>Collection</code>.
		/// </summary>
		/// <returns> The <code>Collection</code>. Is never <code>null</code>. </returns>
		public virtual Collection getCollection()
		{
			return new ArrayList(collection);
		}

		/// <summary>
		/// Returns a formatted string describing the parameters.
		/// </summary>
		/// <returns> a formatted string describing the parameters </returns>
		public override string ToString()
		{
			StringBuffer sb = new StringBuffer();
			sb.append("X509CollectionStoreParameters: [\n");
			sb.append("  collection: " + collection + "\n");
			sb.append("]");
			return sb.ToString();
		}
	}

}