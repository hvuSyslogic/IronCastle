using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// Class representing the DER-type External
	/// </summary>
	public abstract class ASN1External : ASN1Primitive
	{
		protected internal ASN1ObjectIdentifier directReference;
		protected internal ASN1Integer indirectReference;
		protected internal ASN1Primitive dataValueDescriptor;
		protected internal int encoding;
		protected internal ASN1Primitive externalContent;

		/// <summary>
		/// Construct an EXTERNAL object, the input encoding vector must have exactly two elements on it.
		/// <para>
		/// Acceptable input formats are:
		/// <ul>
		/// <li> <seealso cref="ASN1ObjectIdentifier"/> + data <seealso cref="DERTaggedObject"/> (direct reference form)</li>
		/// <li> <seealso cref="ASN1Integer"/> + data <seealso cref="DERTaggedObject"/> (indirect reference form)</li>
		/// <li> Anything but <seealso cref="DERTaggedObject"/> + data <seealso cref="DERTaggedObject"/> (data value form)</li>
		/// </ul>
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IllegalArgumentException"> if input size is wrong, or </exception>
		public ASN1External(ASN1EncodableVector vector)
		{
			int offset = 0;

			ASN1Primitive enc = getObjFromVector(vector, offset);
			if (enc is ASN1ObjectIdentifier)
			{
				directReference = (ASN1ObjectIdentifier)enc;
				offset++;
				enc = getObjFromVector(vector, offset);
			}
			if (enc is ASN1Integer)
			{
				indirectReference = (ASN1Integer) enc;
				offset++;
				enc = getObjFromVector(vector, offset);
			}
			if (!(enc is ASN1TaggedObject))
			{
				dataValueDescriptor = (ASN1Primitive) enc;
				offset++;
				enc = getObjFromVector(vector, offset);
			}

			if (vector.size() != offset + 1)
			{
				throw new IllegalArgumentException("input vector too large");
			}

			if (!(enc is ASN1TaggedObject))
			{
				throw new IllegalArgumentException("No tagged object found in vector. Structure doesn't seem to be of type External");
			}
			ASN1TaggedObject obj = (ASN1TaggedObject)enc;
			setEncoding(obj.getTagNo());
			externalContent = obj.getObject();
		}

		private ASN1Primitive getObjFromVector(ASN1EncodableVector v, int index)
		{
			if (v.size() <= index)
			{
				throw new IllegalArgumentException("too few objects in input vector");
			}

			return v.get(index).toASN1Primitive();
		}

		/// <summary>
		/// Creates a new instance of External
		/// See X.690 for more informations about the meaning of these parameters </summary>
		/// <param name="directReference"> The direct reference or <code>null</code> if not set. </param>
		/// <param name="indirectReference"> The indirect reference or <code>null</code> if not set. </param>
		/// <param name="dataValueDescriptor"> The data value descriptor or <code>null</code> if not set. </param>
		/// <param name="externalData"> The external data in its encoded form. </param>
		public ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, DERTaggedObject externalData) : this(directReference, indirectReference, dataValueDescriptor, externalData.getTagNo(), externalData.toASN1Primitive())
		{
		}

		/// <summary>
		/// Creates a new instance of External.
		/// See X.690 for more informations about the meaning of these parameters </summary>
		/// <param name="directReference"> The direct reference or <code>null</code> if not set. </param>
		/// <param name="indirectReference"> The indirect reference or <code>null</code> if not set. </param>
		/// <param name="dataValueDescriptor"> The data value descriptor or <code>null</code> if not set. </param>
		/// <param name="encoding"> The encoding to be used for the external data </param>
		/// <param name="externalData"> The external data </param>
		public ASN1External(ASN1ObjectIdentifier directReference, ASN1Integer indirectReference, ASN1Primitive dataValueDescriptor, int encoding, ASN1Primitive externalData)
		{
			setDirectReference(directReference);
			setIndirectReference(indirectReference);
			setDataValueDescriptor(dataValueDescriptor);
			setEncoding(encoding);
			setExternalContent(externalData.toASN1Primitive());
		}

		public override ASN1Primitive toDERObject()
		{
			 if (this is DERExternal)
			 {
				 return this;
			 }

			 return new DERExternal(directReference, indirectReference, dataValueDescriptor, encoding, externalContent);
		}

		/* (non-Javadoc)
		 * @see java.lang.Object#hashCode()
		 */
		public override int GetHashCode()
		{
			int ret = 0;
			if (directReference != null)
			{
				ret = directReference.GetHashCode();
			}
			if (indirectReference != null)
			{
				ret ^= indirectReference.GetHashCode();
			}
			if (dataValueDescriptor != null)
			{
				ret ^= dataValueDescriptor.GetHashCode();
			}
			ret ^= externalContent.GetHashCode();
			return ret;
		}

		public override bool isConstructed()
		{
			return true;
		}

		public override int encodedLength()
		{
			return this.getEncoded().Length;
		}

		/* (non-Javadoc)
		 * @see org.bouncycastle.asn1.ASN1Primitive#asn1Equals(org.bouncycastle.asn1.ASN1Primitive)
		 */
		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1External))
			{
				return false;
			}
			if (this == o)
			{
				return true;
			}
			ASN1External other = (ASN1External)o;
			if (directReference != null)
			{
				if (other.directReference == null || !other.directReference.Equals(directReference))
				{
					return false;
				}
			}
			if (indirectReference != null)
			{
				if (other.indirectReference == null || !other.indirectReference.Equals(indirectReference))
				{
					return false;
				}
			}
			if (dataValueDescriptor != null)
			{
				if (other.dataValueDescriptor == null || !other.dataValueDescriptor.Equals(dataValueDescriptor))
				{
					return false;
				}
			}
			return externalContent.Equals(other.externalContent);
		}

		/// <summary>
		/// Returns the data value descriptor </summary>
		/// <returns> The descriptor </returns>
		public virtual ASN1Primitive getDataValueDescriptor()
		{
			return dataValueDescriptor;
		}

		/// <summary>
		/// Returns the direct reference of the external element </summary>
		/// <returns> The reference </returns>
		public virtual ASN1ObjectIdentifier getDirectReference()
		{
			return directReference;
		}

		/// <summary>
		/// Returns the encoding of the content. Valid values are
		/// <ul>
		/// <li><code>0</code> single-ASN1-type</li>
		/// <li><code>1</code> OCTET STRING</li>
		/// <li><code>2</code> BIT STRING</li>
		/// </ul> </summary>
		/// <returns> The encoding </returns>
		public virtual int getEncoding()
		{
			return encoding;
		}

		/// <summary>
		/// Returns the content of this element </summary>
		/// <returns> The content </returns>
		public virtual ASN1Primitive getExternalContent()
		{
			return externalContent;
		}

		/// <summary>
		/// Returns the indirect reference of this element </summary>
		/// <returns> The reference </returns>
		public virtual ASN1Integer getIndirectReference()
		{
			return indirectReference;
		}

		/// <summary>
		/// Sets the data value descriptor </summary>
		/// <param name="dataValueDescriptor"> The descriptor </param>
		private void setDataValueDescriptor(ASN1Primitive dataValueDescriptor)
		{
			this.dataValueDescriptor = dataValueDescriptor;
		}

		/// <summary>
		/// Sets the direct reference of the external element </summary>
		/// <param name="directReferemce"> The reference </param>
		private void setDirectReference(ASN1ObjectIdentifier directReferemce)
		{
			this.directReference = directReferemce;
		}

		/// <summary>
		/// Sets the encoding of the content. Valid values are
		/// <ul>
		/// <li><code>0</code> single-ASN1-type</li>
		/// <li><code>1</code> OCTET STRING</li>
		/// <li><code>2</code> BIT STRING</li>
		/// </ul> </summary>
		/// <param name="encoding"> The encoding </param>
		private void setEncoding(int encoding)
		{
			if (encoding < 0 || encoding > 2)
			{
				throw new IllegalArgumentException("invalid encoding value: " + encoding);
			}
			this.encoding = encoding;
		}

		/// <summary>
		/// Sets the content of this element </summary>
		/// <param name="externalContent"> The content </param>
		private void setExternalContent(ASN1Primitive externalContent)
		{
			this.externalContent = externalContent;
		}

		/// <summary>
		/// Sets the indirect reference of this element </summary>
		/// <param name="indirectReference"> The reference </param>
		private void setIndirectReference(ASN1Integer indirectReference)
		{
			this.indirectReference = indirectReference;
		}
	}

}