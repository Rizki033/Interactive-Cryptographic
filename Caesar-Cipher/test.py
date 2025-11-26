def order_pizza(size, *toppings, **details):
  print(f"Ordered a {size} pizza.")
  for topping in toppings:
    print(f"- {topping}")
  print("\nDetails of the order are:")
  for key, value in details.items():
    print(f"{key}:{value}")
  
order_pizza("large", "pepperoni", "olives", delivery=True, tip=5) 

metrics = {
        'wall_seconds': wall_elapsed,
        'proc_seconds': proc_time_delta,
        'cpu_percent_approx': cpu_percent_approx,
        'py_alloc_current_bytes': current,
        'py_alloc_peak_bytes': peak,
        'process_rss_bytes': rss_bytes,
    }
