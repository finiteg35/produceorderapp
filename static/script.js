/**
 * script.js – Client-side logic for the Produce Order App web interface.
 * Handles cart management, category collapsing, order submission, and mobile UX.
 */

/* ---- Cart state ---- */
let cart = window.__initialCart || [];

/* ---- DOM helpers ---- */
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return document.querySelectorAll(sel); }

/* ---- Update cart UI ---- */
function renderCart(cartData) {
  cart = cartData;

  const itemsContainer = $('#cart-items');
  const badge          = $('#cart-badge');
  const totalDisplay   = $('#cart-total-display');

  if (!itemsContainer) return;

  const total = cart.reduce((acc, e) => acc + (e.qty || 0), 0);
  if (badge)        badge.textContent = total;
  if (totalDisplay) totalDisplay.textContent = total;

  if (cart.length === 0) {
    itemsContainer.innerHTML = `
      <div class="cart-empty" id="cart-empty">
        <span>Your cart is empty.</span><br />
        <span class="cart-empty-hint">Add items from the inventory.</span>
      </div>`;
    return;
  }

  itemsContainer.innerHTML = cart.map((entry) => `
    <div class="cart-item"
         data-category="${escapeHtml(entry.category)}"
         data-item="${escapeHtml(entry.item)}">
      <div class="cart-item-info">
        <span class="cart-item-name">${escapeHtml(entry.item)}</span>
        <span class="cart-item-cat">${escapeHtml(entry.category)}</span>
      </div>
      <div class="cart-item-controls">
        <span class="cart-item-qty">${entry.qty}</span>
        <button class="btn-icon remove-btn"
                data-category="${escapeHtml(entry.category)}"
                data-item="${escapeHtml(entry.item)}"
                title="Remove">🗑</button>
      </div>
    </div>
  `).join('');
}

/* ---- Add item to cart ---- */
function addToCart(category, item, qtyInputId) {
  const input = document.getElementById(qtyInputId);
  const qty = input ? parseInt(input.value, 10) : 1;

  if (isNaN(qty) || qty <= 0) {
    showError('Please enter a valid quantity (at least 1).');
    return;
  }

  fetch('/cart/add', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ category, item, qty }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (data.error) { showError(data.error); return; }
      renderCart(data.cart);
      showAddedFeedback(qtyInputId);
    })
    .catch(() => showError('Could not update cart. Please try again.'));
}

/* ---- Remove item from cart ---- */
function removeFromCart(category, item) {
  fetch('/cart/remove', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ category, item }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (data.error) { showError(data.error); return; }
      renderCart(data.cart);
    })
    .catch(() => showError('Could not remove item. Please try again.'));
}

/* ---- Clear cart ---- */
function clearCart() {
  if (cart.length === 0) return;
  if (!confirm('Clear all items from cart?')) return;

  fetch('/cart/clear', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
    .then(handleJsonResponse)
    .then((data) => renderCart(data.cart))
    .catch(() => showError('Could not clear cart. Please try again.'));
}

/* ---- Submit order (after name is confirmed) ---- */
function submitOrder() {
  if (cart.length === 0) {
    showError('Your cart is empty. Add items before submitting.');
    return;
  }

  const dateInput = $('#delivery-date');
  const isoDate = dateInput ? dateInput.value : '';
  if (!isoDate) {
    showError('Please select a delivery date before submitting.');
    return;
  }

  // Convert ISO date back to "Month DD, YYYY" format expected by the backend
  const deliveryDate = isoDateToMonthStr(isoDate);
  if (!deliveryDate) {
    showError('Please select a valid delivery date before submitting.');
    return;
  }

  // Validate the selected date is among the allowed dates
  const allowedDates = window.__allowedDates || [];
  if (allowedDates.length > 0 && !allowedDates.includes(deliveryDate)) {
    showError('Please select a valid delivery date.');
    return;
  }

  // Show the name prompt modal; actual submission happens after name is confirmed
  window.__pendingDeliveryDate = deliveryDate;
  const nameInput = $('#ordered-by-input');
  if (nameInput) nameInput.value = '';
  const nameModal = $('#name-prompt-modal');
  if (nameModal) {
    nameModal.classList.remove('hidden');
    if (nameInput) nameInput.focus();
  }
}

/* ---- Perform the actual API call once the name has been collected ---- */
function doSubmitOrder(deliveryDate, orderedBy) {
  const btn = $('#submit-order-btn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Submitting…'; }

  fetch('/order/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ delivery_date: deliveryDate, ordered_by: orderedBy }),
  })
    .then(handleJsonResponse)
    .then((data) => {
      if (btn) { btn.disabled = false; btn.textContent = '✅ Submit Order'; }
      if (data.error) { showError(data.error); return; }
      // Clear client-side cart and show success
      renderCart([]);
      showSuccess(data.message || 'Order submitted successfully!');
    })
    .catch(() => {
      if (btn) { btn.disabled = false; btn.textContent = '✅ Submit Order'; }
      showError('Could not submit order. Please try again.');
    });
}

/* ---- Modal helpers ---- */
function showSuccess(message) {
  const modal = $('#success-modal');
  const msg   = $('#success-message');
  if (msg) msg.textContent = message;
  if (modal) modal.classList.remove('hidden');
}

function closeModal() {
  const modal = $('#success-modal');
  if (modal) modal.classList.add('hidden');
}

function closeNamePromptModal() {
  const modal = $('#name-prompt-modal');
  if (modal) modal.classList.add('hidden');
  window.__pendingDeliveryDate = null;
}

function showError(message) {
  const modal = $('#error-modal');
  const msg   = $('#error-message');
  if (msg) msg.textContent = message;
  if (modal) modal.classList.remove('hidden');
}

function closeErrorModal() {
  const modal = $('#error-modal');
  if (modal) modal.classList.add('hidden');
}

/* Close modals on overlay click */
document.addEventListener('click', function (e) {
  if (e.target.classList.contains('modal-overlay')) {
    closeModal();
    closeErrorModal();
    closeNamePromptModal();
  }
});

/* ---- Visual "Added!" feedback on the Add button ---- */
function showAddedFeedback(qtyInputId) {
  const row = document.getElementById(qtyInputId);
  if (!row) return;
  const btn = row.closest('.item-controls')?.querySelector('.btn-add');
  if (!btn) return;
  const original = btn.textContent;
  btn.textContent = '✓ Added';
  btn.style.background = 'var(--green-light)';
  btn.style.color = '#fff';
  setTimeout(() => {
    btn.textContent = original;
    btn.style.background = '';
    btn.style.color = '';
  }, 1200);
}

/* ---- Date format helpers ---- */

// Convert "March 22, 2026" → "2026-03-22" (ISO date string for input[type=date])
function dateStrToISO(dateStr) {
  const months = {
    January: '01', February: '02', March: '03', April: '04',
    May: '05', June: '06', July: '07', August: '08',
    September: '09', October: '10', November: '11', December: '12',
  };
  const match = dateStr.match(/^(\w+)\s+(\d+),\s+(\d{4})$/);
  if (!match) return '';
  const [, month, day, year] = match;
  return `${year}-${months[month]}-${String(day).padStart(2, '0')}`;
}

// Convert "2026-03-22" (ISO) → "March 22, 2026"
function isoDateToMonthStr(isoDate) {
  const months = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  const match = isoDate.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return '';
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (month < 1 || month > 12) return '';
  return `${months[month - 1]} ${String(day).padStart(2, '0')}, ${year}`;
}

/* ---- Pre-select tomorrow's delivery date ---- */
function setDefaultDeliveryDate() {
  const dateInput = $('#delivery-date');
  if (!dateInput) return;

  const allowedDates = window.__allowedDates || [];
  if (allowedDates.length === 0) return;

  const isoAllowedDates = allowedDates.map(dateStrToISO).filter(Boolean);
  if (isoAllowedDates.length === 0) return;

  // Restrict selectable range to first/last allowed date
  dateInput.min = isoAllowedDates[0];
  dateInput.max = isoAllowedDates[isoAllowedDates.length - 1];
}

/* ---- Category collapsing ---- */
function initCategories() {
  $$('.category-section').forEach((section) => {
    section.classList.add('collapsed');
  });
  $$('.category-header').forEach((header) => {
    header.addEventListener('click', function () {
      const section = this.closest('.category-section');
      if (section) section.classList.toggle('collapsed');
    });
  });
}

/* ---- Mobile cart toggle ---- */
function initCartToggle() {
  const toggleBtn = $('#cart-toggle-btn');
  const closeBtn  = $('#cart-close-btn');
  const cartPanel = $('#cart-panel');

  if (!toggleBtn || !cartPanel) return;

  toggleBtn.addEventListener('click', () => {
    cartPanel.classList.toggle('cart-open');
  });

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      cartPanel.classList.remove('cart-open');
    });
  }
}

/* ---- Utility: safe HTML escaping ---- */
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ---- Utility: parse JSON response, throw on HTTP errors ---- */
function handleJsonResponse(resp) {
  if (!resp.ok) {
    return resp.json().catch(() => ({})).then((body) => {
      throw new Error(body.error || `HTTP ${resp.status}`);
    });
  }
  return resp.json();
}

/* ---- Init ---- */
document.addEventListener('DOMContentLoaded', function () {
  initCategories();
  initCartToggle();
  initEventDelegation();
  setDefaultDeliveryDate();

  // Ensure cart badge is accurate on page load
  const badge = $('#cart-badge');
  if (badge && cart.length > 0) {
    const total = cart.reduce((acc, e) => acc + (e.qty || 0), 0);
    badge.textContent = total;
  }
});

/* ---- Event delegation for dynamic buttons ---- */
function initEventDelegation() {
  // "Add to cart" buttons in inventory panel
  const inventoryPanel = $('#inventory-panel');
  if (inventoryPanel) {
    inventoryPanel.addEventListener('click', function (e) {
      const btn = e.target.closest('.btn-add');
      if (!btn) return;
      const category = btn.dataset.category;
      const item     = btn.dataset.item;
      const qtyId    = btn.dataset.qtyid;
      addToCart(category, item, qtyId);
    });
  }

  // Remove buttons in cart panel (event delegation on the cart items container)
  const cartItems = $('#cart-items');
  if (cartItems) {
    cartItems.addEventListener('click', function (e) {
      const btn = e.target.closest('.remove-btn');
      if (!btn) return;
      removeFromCart(btn.dataset.category, btn.dataset.item);
    });
  }

  // Submit order button
  const submitBtn = $('#submit-order-btn');
  if (submitBtn) submitBtn.addEventListener('click', submitOrder);

  // Clear cart button
  const clearBtn = $('#clear-cart-btn');
  if (clearBtn) clearBtn.addEventListener('click', clearCart);

  // Modal buttons
  const continueBtn = $('#modal-continue-btn');
  if (continueBtn) continueBtn.addEventListener('click', closeModal);

  const errorOkBtn = $('#modal-error-ok-btn');
  if (errorOkBtn) errorOkBtn.addEventListener('click', closeErrorModal);

  // Name prompt modal buttons
  const nameConfirmBtn = $('#name-prompt-confirm-btn');
  if (nameConfirmBtn) {
    nameConfirmBtn.addEventListener('click', function () {
      const nameInput = $('#ordered-by-input');
      const orderedBy = nameInput ? nameInput.value.trim() : '';
      if (!orderedBy) {
        nameInput && nameInput.focus();
        return;
      }
      const deliveryDate = window.__pendingDeliveryDate;
      if (!deliveryDate) return;
      closeNamePromptModal();
      doSubmitOrder(deliveryDate, orderedBy);
    });
  }

  const nameCancelBtn = $('#name-prompt-cancel-btn');
  if (nameCancelBtn) nameCancelBtn.addEventListener('click', closeNamePromptModal);

  // Allow pressing Enter in the name input to confirm
  const nameInput = $('#ordered-by-input');
  if (nameInput) {
    nameInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        const confirmBtn = $('#name-prompt-confirm-btn');
        if (confirmBtn) confirmBtn.click();
      }
    });
  }
}
