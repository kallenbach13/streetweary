import { useEffect, useState } from 'react'
import ProductCard from './ProductCard'
import { useDispatch, useSelector } from 'react-redux'
import {  selectAllProducts, selectFetchAllProductsStatus } from '../../features/products/productsSlice'
import { needsCheckoutRedirectUpdated } from '../../features/cart/cartSlice'
import ReactPaginate from 'react-paginate'
import './Pagination.css'
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome'
import { useHistory, useParams } from 'react-router-dom'

const ProductList = () => {
  
  const products = useSelector(selectAllProducts)
  const productsStatus = useSelector(selectFetchAllProductsStatus)

  const [data, setData] = useState([])
  const [perPage] = useState(8)
  const [pageCount, setPageCount] = useState(0)
  const { productOffset = 0 }= useParams()
  let history = useHistory()
  const dispatch = useDispatch()

  useEffect(() => {
    dispatch(needsCheckoutRedirectUpdated(false))
  }, [dispatch])

  useEffect(() => {
    const slice = Object.keys(products).slice(productOffset, productOffset + perPage)
    const postData = slice.map(keyName =>
            <ProductCard
              key={products[keyName].id}
              product={products[keyName]} />)
    setData(postData)
    setPageCount(Math.ceil(Object.keys(products).length / perPage))
  }, [products, productOffset, perPage])

  const handlePageClick = (e) => {
    const selectedPage = e.selected
    window.scrollTo(0, 0);
    history.push(`/${Math.ceil(selectedPage * perPage)}`)
  }

  return (
            <div className="flex flex-col flex-grow">
   
            { productsStatus === 'loading' && <FontAwesomeIcon  className="mt-20 mx-auto" icon="fas fa-spinner" size="4x" spin/>}

              { productsStatus === 'failed' &&
                <div className="p-4 mt-20 mx-auto max-w-screen-2xl">
                  <h2 className="text-lg text-center">Problem connecting with the server.</h2>
                </div>}

              { productsStatus === 'succeeded' &&
              <div className="flex flex-grow flex-col">
                <div className="flex-grow">
                  <div className="p-4 flex flex-wrap justify-center max-w-screen-2xl mx-auto">
                    {data}
                  </div>
                </div>
                <div className="p-4 flex justify-center mx-auto">
                  <ReactPaginate
                                previousLabel={"Previous"}
                                nextLabel={"Next"}
                                breakLabel={"..."}
                                breakClassName={"break-me"}
                                pageCount={pageCount}
                                marginPagesDisplayed={2}
                                pageRangeDisplayed={5}
                                onPageChange={handlePageClick}
                                containerClassName={"pagination"}
                                subContainerClassName={"pages pagination"}
                                activeClassName={"active"}/>
                </div>
              </div>
              }
            </div>
    )
  }
  
  export default ProductList